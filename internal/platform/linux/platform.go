// Package linux runs the engine's tunnel on Linux as root: kernel ESP on an XFRM interface or a
// TUN device, policy routing, systemd-resolved and, for split domains, nftables.
package linux

import (
	"errors"
	"io"
	"log"
	"net"
	"os"

	"github.com/dvjn/globalprotect-native/internal/engine"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/hip"
	"github.com/dvjn/globalprotect-native/internal/platform/linux/dns"
	"github.com/dvjn/globalprotect-native/internal/platform/linux/link"
	"github.com/dvjn/globalprotect-native/internal/platform/linux/nft"
	"github.com/dvjn/globalprotect-native/internal/platform/linux/route"
	"github.com/dvjn/globalprotect-native/internal/platform/linux/xfrm"
	"github.com/dvjn/globalprotect-native/internal/split"
)

const deviceName = "gpn0"

// espInterfaceID is the XFRM if_id that ties gpn's ESP policies to its interface.
const espInterfaceID = 0x4501

// splitMark is the firewall mark of split traffic. An ip rule sends it to the main table when
// it goes around the tunnel, or to the tunnel's table when it goes through it.
const splitMark = 0x4501

// Platform implements engine.Platform.
type Platform struct {
	// UserHome is reported to the HIP check as a drive next to "/".
	UserHome string
	// Log receives what goes wrong in the background, such as failed DNS queries; nil sends it
	// to stderr.
	Log *log.Logger
}

func (platform Platform) logger() *log.Logger {
	if platform.Log == nil {
		return log.New(os.Stderr, "", 0)
	}
	return platform.Log
}

// Dialer is the default: policy routing keeps the gateways outside the tunnel.
func (Platform) Dialer() *net.Dialer {
	return nil
}

func (Platform) RemoveLeftovers() error {
	return RemoveLeftovers()
}

func (Platform) OuterAddress(gateway net.IP) (net.IP, error) {
	return xfrm.OuterAddress(gateway)
}

func (Platform) OpenESP(network engine.Network, config gp.ESPConfig) (engine.ESP, error) {
	esp, err := xfrm.OpenESP(deviceName, espInterfaceID, network.ClientIP, network.Gateway, network.MTU, config)
	if err != nil {
		return nil, err
	}
	return esp, nil
}

func (Platform) OpenDevice(network engine.Network) (io.ReadWriteCloser, error) {
	device, err := link.Create(deviceName)
	if err != nil {
		return nil, err
	}
	if err := device.Configure(network.ClientIP, network.MTU); err != nil {
		device.Close()
		return nil, err
	}
	return device, nil
}

func (platform Platform) HIPInventory() ([]hip.Product, hip.Facts) {
	drives := []string{"/"}
	if platform.UserHome != "" {
		drives = append(drives, platform.UserHome)
	}
	return detectProducts(), collectFacts(drives)
}

// ApplyNetwork installs the routes, the split-domain forwarder and the DNS settings on the
// tunnel device, and returns how to undo them in reverse order.
func (platform Platform) ApplyNetwork(network engine.Network) (func(), error) {
	var undoSteps []func() error
	undo := func() {
		var errs []error
		for i := len(undoSteps) - 1; i >= 0; i-- {
			errs = append(errs, undoSteps[i]())
		}
		if err := errors.Join(errs...); err != nil {
			platform.logger().Println("Cleanup failed:", err)
		}
	}
	applied := false
	defer func() {
		if !applied {
			undo()
		}
	}()

	routing, err := route.Apply(routingPlan(network))
	if err != nil {
		return nil, err
	}
	undoSteps = append(undoSteps, routing.Remove)

	dnsSettings := dnsSettings(network)
	if !network.Domains.Empty() {
		firewall, err := nft.InstallFirewall(deviceName, splitDirection(network), splitMark)
		if err != nil {
			return nil, err
		}
		undoSteps = append(undoSteps, firewall.Remove)

		forwarder, err := split.StartForwarder(network.ClientIP, network.DNSServers, network.Domains,
			splitDirection(network), firewall, platform.logger())
		if err != nil {
			return nil, err
		}
		undoSteps = append(undoSteps, forwarder.Close)
		dnsSettings.Servers = []string{network.ClientIP.String()}
	}

	restoreDNS, err := dns.Apply(dnsSettings)
	if err != nil {
		return nil, err
	}
	undoSteps = append(undoSteps, restoreDNS)
	applied = true
	return undo, nil
}

// routingPlan is the policy routing for the network. Matched split domains carry splitMark,
// which sends them around the tunnel or, include-only, through it.
func routingPlan(network engine.Network) route.Plan {
	plan := route.Plan{
		Device:             deviceName,
		Gateways:           network.Gateways,
		ExcludeRoutes:      network.ExcludeRoutes,
		LocalNetworkAccess: network.LocalNetworkAccess,
	}
	if !network.IncludeOnly {
		plan.IncludeRoutes = network.Routes
		if !network.Domains.Empty() {
			plan.ExcludeMark = splitMark
		}
		return plan
	}
	// The tunnel's table reaches everything; rules pick what goes there.
	plan.IncludeOnly = true
	plan.IncludeRoutes = []*net.IPNet{{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}}
	plan.OnlyRoutes = network.Routes
	if !network.Domains.Empty() {
		plan.OnlyMark = splitMark
	}
	return plan
}

// dnsSettings sends every query to the tunnel's servers or, include-only, only the queries for
// the include domains and the DNS suffixes.
func dnsSettings(network engine.Network) dns.Settings {
	settings := dns.Settings{Device: deviceName, Servers: network.DNSServers, Suffixes: network.DNSSuffixes}
	if network.IncludeOnly {
		settings.Selective = true
		if !network.Domains.Empty() {
			settings.RoutingDomains = network.Domains.RoutingDomains()
		}
	}
	return settings
}

func splitDirection(network engine.Network) split.Direction {
	if network.IncludeOnly {
		return split.Through
	}
	return split.Around
}

// RemoveLeftovers deletes rules, the tunnel device, XFRM state, the split table and a
// replaced resolv.conf that an earlier run did not get to remove. resolved forgets the
// device's DNS settings together with the device.
func RemoveLeftovers() error {
	return errors.Join(
		route.RemoveLeftovers(),
		dns.RestoreLeftovers(),
		nft.RemoveLeftovers(),
		xfrm.RemoveLeftovers(deviceName, espInterfaceID),
	)
}
