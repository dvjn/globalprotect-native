// Package tun creates and configures a Linux TUN device.
package tun

import (
	"fmt"
	"net"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/dvjn/globalprotect-native/internal/route"
)

// Device is a TUN device. Closing it deletes the device and every route through it.
type Device struct {
	Name string
	file *os.File
}

// Create makes a TUN device that carries bare IP packets.
func Create(name string) (*Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	request, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("create %s: %w", name, err)
	}

	// A non-blocking descriptor lets Go's poller interrupt a pending Read on Close.
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &Device{Name: request.Name(), file: os.NewFile(uintptr(fd), "/dev/net/tun")}, nil
}

// Configure sets the device's address and MTU and brings it up.
func (device *Device) Configure(address net.IP, mtu int) error {
	link, err := netlink.LinkByName(device.Name)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("set MTU: %w", err)
	}
	return ConfigureLink(link, address)
}

// ConfigureLink gives link the host address and brings it up.
func ConfigureLink(link netlink.Link, address net.IP) error {
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: route.HostPrefix(address)}); err != nil {
		return fmt.Errorf("add address %s: %w", address, err)
	}
	return netlink.LinkSetUp(link)
}

func (device *Device) Read(packet []byte) (int, error) {
	return device.file.Read(packet)
}

func (device *Device) Write(packet []byte) (int, error) {
	return device.file.Write(packet)
}

// Close deletes the device.
func (device *Device) Close() error {
	return device.file.Close()
}
