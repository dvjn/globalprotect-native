// Package engine runs a GlobalProtect tunnel: it logs in to a gateway, reports the host and
// carries traffic until the tunnel ends. Everything it needs from the operating system goes
// through a Platform, so the Linux daemon and other systems can share it.
package engine

import (
	"errors"
	"io"
	"net"

	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/hip"
)

// Platform is what the engine needs from the operating system.
type Platform interface {
	// Dialer connects to the portal and gateways outside the tunnel; nil means the default.
	Dialer() *net.Dialer
	// RemoveLeftovers undoes what an earlier tunnel left behind when it was killed.
	RemoveLeftovers() error
	// OuterAddress is the local address that reaches the gateway. When it changes, the
	// network has changed and the tunnel has to be built again.
	OuterAddress(gateway net.IP) (net.IP, error)
	// OpenESP sets up ESP to the network's gateway, with the system doing the encryption.
	OpenESP(network Network, config gp.ESPConfig) (ESP, error)
	// OpenDevice creates the device whose packets the SSL tunnel carries.
	OpenDevice(network Network) (io.ReadWriteCloser, error)
	// ApplyNetwork sends the network's traffic and DNS into the tunnel once it carries
	// traffic, and returns how to undo that.
	ApplyNetwork(network Network) (undo func(), err error)
	// HIPInventory is the security products and machine facts the HIP report describes.
	HIPInventory() ([]hip.Product, hip.Facts)
}

// ESP is a tunnel the system carries over ESP. The engine keeps it alive with magic pings.
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
