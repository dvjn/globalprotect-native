package mobile

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/dvjn/globalprotect-native/internal/engine"
	"github.com/dvjn/globalprotect-native/internal/split"
)

// splitDevice splits split domains by their addresses, as the Linux DNS forwarder does, but by
// watching the DNS answers the tunnel carries: Android routes only by address, and the VPN's
// DNS servers are reached through the tunnel.
//
// Before an answer for a matching name reaches the app, it establishes the VPN again with the
// answer's addresses routed through the tunnel or, for exclude domains, around it. Android
// hands the VPN network over to the new device, so open connections keep working. Addresses
// stay split for the rest of the connection, whatever their TTL.
type splitDevice struct {
	app     App
	network engine.Network

	lock   sync.Mutex
	file   *os.File
	split  map[string]bool
	closed bool
}

func newSplitDevice(app App, network engine.Network, file *os.File) *splitDevice {
	return &splitDevice{app: app, network: network, file: file, split: map[string]bool{}}
}

func (device *splitDevice) current() *os.File {
	device.lock.Lock()
	defer device.lock.Unlock()
	return device.file
}

// Read returns the next packet for the gateway. It answers AAAA queries for include domains
// itself, as the Linux forwarder does: only IPv4 is split.
func (device *splitDevice) Read(packet []byte) (int, error) {
	for {
		file := device.current()
		length, err := file.Read(packet)
		if err != nil {
			// A Read of the device that was just replaced fails; carry on with the new one.
			if file != device.current() {
				continue
			}
			return length, err
		}
		if device.network.IncludeOnly {
			if reply, refused := split.IPv6Refusal(packet[:length], device.network.Domains); refused {
				if _, err := device.current().Write(reply); err != nil {
					return 0, err
				}
				continue
			}
		}
		return length, nil
	}
}

// Write gives a packet from the gateway to the app, once its addresses are split.
func (device *splitDevice) Write(packet []byte) (int, error) {
	if addresses, _, matched := split.AnswerAddresses(packet, device.network.Domains); matched {
		if err := device.add(addresses); err != nil {
			device.app.Log("split domains: " + err.Error())
		}
	}
	return device.current().Write(packet)
}

// add establishes the VPN again when any of addresses is new.
func (device *splitDevice) add(addresses []net.IP) error {
	device.lock.Lock()
	defer device.lock.Unlock()
	if device.closed {
		return nil
	}
	network := device.network
	var added []*net.IPNet
	for _, address := range addresses {
		if address = address.To4(); address != nil && !device.split[address.String()] {
			device.split[address.String()] = true
			added = append(added, &net.IPNet{IP: address, Mask: net.CIDRMask(32, 32)})
		}
	}
	if len(added) == 0 {
		return nil
	}
	for address := range device.split {
		prefix := &net.IPNet{IP: net.ParseIP(address).To4(), Mask: net.CIDRMask(32, 32)}
		if network.IncludeOnly {
			network.Routes = append(network.Routes, prefix)
		} else {
			network.ExcludeRoutes = append(network.ExcludeRoutes, prefix)
		}
	}

	fd, err := device.app.Establish(tunnelConfig(network))
	if err != nil {
		for _, prefix := range added {
			delete(device.split, prefix.IP.String())
		}
		return fmt.Errorf("could not split %s: %w", engine.JoinPrefixes(added), err)
	}
	file, err := openDevice(fd)
	if err != nil {
		return err
	}
	old := device.file
	device.file = file
	old.Close()
	direction := "around"
	if network.IncludeOnly {
		direction = "through"
	}
	device.app.Log(fmt.Sprintf("split domains: %s now go %s the tunnel", engine.JoinPrefixes(added), direction))
	return nil
}

func (device *splitDevice) Close() error {
	device.lock.Lock()
	defer device.lock.Unlock()
	if device.closed {
		return errors.New("already closed")
	}
	device.closed = true
	return device.file.Close()
}
