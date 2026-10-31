package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/dvjn/globalprotect-native/internal/engine"
	"github.com/dvjn/globalprotect-native/internal/hip"
)

// platform runs the engine's tunnel in the app's VpnService. Android has no kernel ESP for
// apps, so the engine encrypts ESP itself.
type platform struct {
	app    App
	dialer *net.Dialer
}

var _ engine.Platform = (*platform)(nil)

func newPlatform(app App) *platform {
	return &platform{app: app, dialer: protectedDialer(app)}
}

// protectedDialer connects outside the VPN: it protects every socket before connecting, and
// looks names up with the network's DNS server through such sockets.
func protectedDialer(app App) *net.Dialer {
	dialer := &net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
		protected := false
		if err := raw.Control(func(fd uintptr) { protected = app.Protect(int(fd)) }); err != nil {
			return err
		}
		if !protected {
			return errors.New("the app could not keep a socket outside the VPN")
		}
		return nil
	}}
	lookups := *dialer
	dialer.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Android has no /etc/resolv.conf, so Go would ask localhost.
			if server := app.DNSServer(); server != "" {
				address = net.JoinHostPort(server, "53")
			}
			return lookups.DialContext(ctx, network, address)
		},
	}
	return dialer
}

func (platform *platform) Dialer() *net.Dialer {
	return platform.dialer
}

// RemoveLeftovers has nothing to do: Android removes a VPN device with the process that made it.
func (platform *platform) RemoveLeftovers() error {
	return nil
}

func (platform *platform) Establish(network engine.Network) (io.ReadWriteCloser, error) {
	fd, err := platform.app.Establish(tunnelConfig(network))
	if err != nil {
		return nil, err
	}
	// A non-blocking descriptor lets Go's poller interrupt a pending Read on Close.
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "vpn"), nil
}

func tunnelConfig(network engine.Network) *TunnelConfig {
	return &TunnelConfig{
		ClientIP:      network.ClientIP.String(),
		MTU:           network.MTU,
		Routes:        joinPrefixes(network.Routes),
		ExcludeRoutes: joinPrefixes(network.ExcludeRoutes),
		DNSServers:    strings.Join(network.DNSServers, ","),
		SearchDomains: strings.Join(network.DNSSuffixes, ","),
		IncludeOnly:   network.IncludeOnly,
		Domains:       strings.Join(network.Domains.Entries(), ","),
	}
}

func joinPrefixes(prefixes []*net.IPNet) string {
	var joined []string
	for _, prefix := range prefixes {
		joined = append(joined, prefix.String())
	}
	return strings.Join(joined, ",")
}

// inventory is the JSON of App.HIPInventory.
type inventory struct {
	Products   []hip.Product   `json:"products"`
	Drives     []hip.Drive     `json:"drives"`
	Interfaces []hip.Interface `json:"interfaces"`
}

func (platform *platform) HIPInventory() ([]hip.Product, hip.Facts) {
	var found inventory
	if text := platform.app.HIPInventory(); text != "" {
		if err := json.Unmarshal([]byte(text), &found); err != nil {
			platform.app.Log("HIP inventory: " + err.Error())
		}
	}
	return found.Products, hip.Facts{Drives: found.Drives, Interfaces: found.Interfaces}
}
