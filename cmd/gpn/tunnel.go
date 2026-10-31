package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/dvjn/globalprotect-native/internal/dns"
	"github.com/dvjn/globalprotect-native/internal/engine"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/hip"
	"github.com/dvjn/globalprotect-native/internal/route"
	"github.com/dvjn/globalprotect-native/internal/split"
	"github.com/dvjn/globalprotect-native/internal/tun"
	"github.com/dvjn/globalprotect-native/internal/xfrm"
)

const deviceName = "gpn0"

// espInterfaceID is the XFRM if_id that ties gpn's ESP policies to its interface.
const espInterfaceID = 0x4501

// linuxPlatform runs the engine's tunnel as root: kernel ESP on an XFRM interface or a TUN
// device, policy routing, systemd-resolved and, for split domains, nftables.
type linuxPlatform struct {
	// userHome is reported as a drive next to "/".
	userHome string
}

// Dialer is the default: policy routing keeps the gateways outside the tunnel.
func (linuxPlatform) Dialer() *net.Dialer {
	return nil
}

func (linuxPlatform) RemoveLeftovers() error {
	return removeLeftovers()
}

func (linuxPlatform) OuterAddress(gateway net.IP) (net.IP, error) {
	return xfrm.OuterAddress(gateway)
}

func (linuxPlatform) OpenESP(network engine.Network, config gp.ESPConfig) (engine.ESP, error) {
	esp, err := xfrm.OpenESP(deviceName, espInterfaceID, network.ClientIP, network.Gateway, network.MTU, config)
	if err != nil {
		return nil, err
	}
	return esp, nil
}

func (linuxPlatform) OpenDevice(network engine.Network) (io.ReadWriteCloser, error) {
	device, err := tun.Create(deviceName)
	if err != nil {
		return nil, err
	}
	if err := device.Configure(network.ClientIP, network.MTU); err != nil {
		device.Close()
		return nil, err
	}
	return device, nil
}

func (platform linuxPlatform) HIPInventory() ([]hip.Product, hip.Facts) {
	drives := []string{"/"}
	if platform.userHome != "" {
		drives = append(drives, platform.userHome)
	}
	return hip.DetectProducts(), hip.CollectFacts(drives)
}

// ApplyNetwork installs the routes, the split-domain forwarder and the DNS settings on the
// tunnel device, and returns how to undo them in reverse order.
func (linuxPlatform) ApplyNetwork(network engine.Network) (undo func(), err error) {
	var undoSteps []func() error
	undo = func() {
		var errs []error
		for i := len(undoSteps) - 1; i >= 0; i-- {
			errs = append(errs, undoSteps[i]())
		}
		if err := errors.Join(errs...); err != nil {
			fmt.Fprintln(os.Stderr, "Cleanup failed:", err)
		}
	}
	defer func() {
		if err != nil {
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
		firewall, err := split.InstallFirewall(deviceName, splitDirection(network))
		if err != nil {
			return nil, err
		}
		undoSteps = append(undoSteps, firewall.Remove)

		forwarder, err := split.StartForwarder(network.ClientIP, network.DNSServers, network.Domains, firewall, logger)
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
	return undo, nil
}

// routingPlan is the policy routing for the network. Matched split domains carry split.Mark,
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
			plan.ExcludeMark = split.Mark
		}
		return plan
	}
	// The tunnel's table reaches everything; rules pick what goes there.
	plan.IncludeOnly = true
	plan.IncludeRoutes = []*net.IPNet{{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}}
	plan.OnlyRoutes = network.Routes
	if !network.Domains.Empty() {
		plan.OnlyMark = split.Mark
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

// runCleanup removes what a killed daemon left behind, so the network works again without it.
func runCleanup(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: gpn cleanup")
	}
	if os.Geteuid() != 0 {
		return errors.New("cleanup changes network settings; run it as root")
	}
	lock, err := lockDaemon()
	if err != nil {
		return fmt.Errorf("%w; stop it instead, it cleans up after itself", err)
	}
	defer lock.Close()
	return removeLeftovers()
}

// removeLeftovers deletes rules, the tunnel device, XFRM state, the split table and a
// replaced resolv.conf that an earlier run did not get to remove. resolved forgets the
// device's DNS settings together with the device.
func removeLeftovers() error {
	return errors.Join(
		route.RemoveLeftovers(),
		dns.RestoreLeftovers(),
		split.RemoveLeftovers(),
		xfrm.RemoveLeftovers(deviceName, espInterfaceID),
	)
}
