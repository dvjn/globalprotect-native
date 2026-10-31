// Package engine runs a GlobalProtect tunnel: it logs in to a gateway, reports the host and
// carries traffic until the tunnel ends. Everything it needs from the operating system goes
// through a Platform, so the Linux daemon and other systems can share it.
package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/hip"
)

// Platform is what the engine needs from the operating system.
type Platform interface {
	// Dialer connects outside the tunnel: to the portal, the gateways and their ESP port. Its
	// Resolver, when set, looks up their names. nil means the default dialer.
	Dialer() *net.Dialer
	// RemoveLeftovers undoes what an earlier tunnel left behind when it was killed.
	RemoveLeftovers() error
	// Establish creates the tunnel device with the network's address, and sends the network's
	// traffic and DNS into it. Closing the device undoes all of that.
	Establish(network Network) (io.ReadWriteCloser, error)
	// HIPProfile is what the platform detects for the HIP report: at least the security
	// products, drives and interfaces, and the OS vendor. The engine fills in the rest from the
	// login's identity.
	HIPProfile() hip.Profile
}

// KernelESP is a Platform whose kernel can carry ESP, which is faster than the engine
// encrypting it. Without it, or with kernel_esp off, the engine encrypts ESP itself and
// carries it through the device from Establish.
type KernelESP interface {
	// OpenKernelESP sets up ESP to the network's gateway, with the kernel doing the encryption.
	OpenKernelESP(network Network, config gp.ESPConfig) (ESP, error)
	// ApplyNetwork sends the network's traffic and DNS into the kernel's ESP tunnel, and
	// returns how to undo that.
	ApplyNetwork(network Network) (undo func(), err error)
}

// ESP is a tunnel the kernel carries over ESP. The engine keeps it alive with magic pings.
type ESP interface {
	SendMagicPing(sequence uint16) error
	// ReadMagicReply waits briefly for the gateway's answer to a magic ping. An error with a
	// Timeout method that reports true means no answer arrived yet.
	ReadMagicReply() error
	Close() error
}

func isTimeout(err error) bool {
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

// orDefault is dialer, or the default dialer when the platform has none.
func orDefault(dialer *net.Dialer) *net.Dialer {
	if dialer == nil {
		return &net.Dialer{}
	}
	return dialer
}

// resolver looks up names the way dialer does.
func resolver(dialer *net.Dialer) *net.Resolver {
	if dialer == nil || dialer.Resolver == nil {
		return net.DefaultResolver
	}
	return dialer.Resolver
}

// outerAddress is the local address that reaches gateway. Connecting a UDP socket sends
// nothing, but has the system choose the source address, outside the tunnel as dialer does.
func outerAddress(dialer *net.Dialer, gateway net.IP) (net.IP, error) {
	connection, err := orDefault(dialer).DialContext(context.Background(), "udp4", net.JoinHostPort(gateway.String(), "443"))
	if err != nil {
		return nil, fmt.Errorf("route to gateway %s: %w", gateway, err)
	}
	defer connection.Close()
	return connection.LocalAddr().(*net.UDPAddr).IP, nil
}
