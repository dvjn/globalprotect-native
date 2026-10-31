// Package xfrm carries the tunnel over kernel ESP: an XFRM interface with ESP-in-UDP states
// and policies, so the kernel encrypts and decrypts the traffic.
package xfrm

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/platform/linux/link"
	"github.com/dvjn/globalprotect-native/internal/tunnel"
)

// ESP carries traffic as ESP in UDP, with the kernel doing the encryption.
// It is route-based: an XFRM interface plus wildcard policies bound to that interface's
// if_id, so only traffic routed into the interface is encrypted.
type ESP struct {
	Name     string
	link     netlink.Link
	socket   *net.UDPConn
	states   []*netlink.XfrmState
	policies []*netlink.XfrmPolicy
	icmp     int
	clientIP net.IP
	magic    net.IP
}

// OpenESP sets up the XFRM interface name with if_id ifid, its ESP states and policies.
// gateway is the gateway's public address: the ESP peer and the target of the magic ping.
func OpenESP(name string, ifid uint32, clientIP, gateway net.IP, mtu int, config gp.ESPConfig) (esp *ESP, err error) {
	esp = &ESP{Name: name, clientIP: clientIP, magic: gateway, icmp: -1}
	defer func() {
		if err != nil {
			esp.Close()
		}
	}()

	if err := esp.openEncapSocket(); err != nil {
		return nil, err
	}
	localPort := esp.socket.LocalAddr().(*net.UDPAddr).Port
	outer, err := outerAddress(gateway)
	if err != nil {
		return nil, err
	}

	outbound, inbound, err := espStates(config, outer, gateway, localPort, int(ifid))
	if err != nil {
		return nil, err
	}
	for _, state := range []*netlink.XfrmState{outbound, inbound} {
		if err := netlink.XfrmStateAdd(state); err != nil {
			return nil, fmt.Errorf("add ESP state SPI %#x: %w", state.Spi, err)
		}
		esp.states = append(esp.states, state)
	}

	esp.link = &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: mtu}, Ifid: ifid}
	if err := netlink.LinkAdd(esp.link); err != nil {
		esp.link = nil
		return nil, fmt.Errorf("create %s: %w", name, err)
	}
	if err := link.ConfigureLink(esp.link, clientIP); err != nil {
		return nil, err
	}

	anywhere := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	for _, policy := range []*netlink.XfrmPolicy{
		{Src: anywhere, Dst: anywhere, Dir: netlink.XFRM_DIR_OUT, Ifid: int(ifid), Tmpls: []netlink.XfrmPolicyTmpl{
			{Src: outer, Dst: gateway, Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TUNNEL}}},
		{Src: anywhere, Dst: anywhere, Dir: netlink.XFRM_DIR_IN, Ifid: int(ifid), Tmpls: []netlink.XfrmPolicyTmpl{
			{Src: gateway, Dst: outer, Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TUNNEL}}},
	} {
		if err := netlink.XfrmPolicyAdd(policy); err != nil {
			return nil, fmt.Errorf("add ESP policy: %w", err)
		}
		esp.policies = append(esp.policies, policy)
	}

	if err := esp.openPingSocket(); err != nil {
		return nil, err
	}
	return esp, nil
}

// openEncapSocket opens the UDP socket the kernel decapsulates incoming ESP on.
func (esp *ESP) openEncapSocket() error {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return err
	}
	esp.socket = socket

	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_ENCAP, unix.UDP_ENCAP_ESPINUDP)
	}); err != nil {
		return err
	}
	if socketErr != nil {
		return fmt.Errorf("enable ESP-in-UDP: %w", socketErr)
	}
	return nil
}

// openPingSocket opens a raw ICMP socket on the XFRM interface for the magic ping.
// Binding to the device sends the ping into the tunnel although the routing table
// reaches the gateway's address over the physical network.
func (esp *ESP) openPingSocket() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		return err
	}
	esp.icmp = fd
	if err := unix.BindToDevice(fd, esp.Name); err != nil {
		return fmt.Errorf("bind ping socket to %s: %w", esp.Name, err)
	}
	address := &unix.SockaddrInet4{}
	copy(address.Addr[:], esp.clientIP.To4())
	if err := unix.Bind(fd, address); err != nil {
		return err
	}
	timeout := unix.NsecToTimeval(int64(time.Second))
	return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout)
}

// outerAddress is the local address the kernel uses to reach the gateway. ESP states are
// bound to it, so a new address means the tunnel has to be built again.
func outerAddress(gateway net.IP) (net.IP, error) {
	routes, err := netlink.RouteGet(gateway)
	if err != nil {
		return nil, fmt.Errorf("route to gateway %s: %w", gateway, err)
	}
	if len(routes) == 0 || routes[0].Src == nil {
		return nil, fmt.Errorf("no source address for gateway %s", gateway)
	}
	return routes[0].Src, nil
}

func espStates(config gp.ESPConfig, outer, gateway net.IP, localPort, ifid int) (outbound, inbound *netlink.XfrmState, err error) {
	newState := func(source, destination net.IP, keys gp.ESPKeys, sourcePort, destinationPort, replayWindow int) (*netlink.XfrmState, error) {
		state := &netlink.XfrmState{
			Src:          source,
			Dst:          destination,
			Proto:        netlink.XFRM_PROTO_ESP,
			Mode:         netlink.XFRM_MODE_TUNNEL,
			Spi:          int(keys.SPI),
			ReplayWindow: replayWindow,
			Ifid:         ifid,
			Encap: &netlink.XfrmStateEncap{
				Type:            netlink.XFRM_ENCAP_ESPINUDP,
				SrcPort:         sourcePort,
				DstPort:         destinationPort,
				OriginalAddress: net.IPv4zero,
			},
		}
		return state, setAlgorithms(state, config, keys)
	}

	outbound, err = newState(outer, gateway, config.ClientToServer, localPort, config.UDPPort, 0)
	if err != nil {
		return nil, nil, err
	}
	inbound, err = newState(gateway, outer, config.ServerToClient, config.UDPPort, localPort, 32)
	return outbound, inbound, err
}

// setAlgorithms maps the gateway's cipher names to kernel algorithms.
// GCM keys carry a 32-bit salt after the AES key, as RFC 4106 specifies.
func setAlgorithms(state *netlink.XfrmState, config gp.ESPConfig, keys gp.ESPKeys) error {
	switch config.Encryption {
	case "aes-128-gcm", "aes-256-gcm":
		state.Aead = &netlink.XfrmStateAlgo{Name: "rfc4106(gcm(aes))", Key: keys.EncryptionKey, ICVLen: 128}
		return nil
	case "aes-128-cbc", "aes-256-cbc":
		state.Crypt = &netlink.XfrmStateAlgo{Name: "cbc(aes)", Key: keys.EncryptionKey}
	default:
		return fmt.Errorf("unsupported ESP cipher %q", config.Encryption)
	}

	switch config.Integrity {
	case "sha1":
		state.Auth = &netlink.XfrmStateAlgo{Name: "hmac(sha1)", Key: keys.IntegrityKey, TruncateLen: 96}
	case "sha256":
		state.Auth = &netlink.XfrmStateAlgo{Name: "hmac(sha256)", Key: keys.IntegrityKey, TruncateLen: 128}
	case "md5":
		state.Auth = &netlink.XfrmStateAlgo{Name: "hmac(md5)", Key: keys.IntegrityKey, TruncateLen: 96}
	default:
		return fmt.Errorf("unsupported ESP integrity algorithm %q", config.Integrity)
	}
	return nil
}

// SendMagicPing sends the ICMP echo request that tells the gateway ESP is alive.
func (esp *ESP) SendMagicPing(sequence uint16) error {
	message := tunnel.MagicPing(sequence)
	destination := &unix.SockaddrInet4{}
	copy(destination.Addr[:], esp.magic.To4())
	for {
		err := unix.Sendto(esp.icmp, message, 0, destination)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// errNoReply means the ping socket's one-second read timeout passed without a magic reply.
// It is a timeout, which tells the caller to keep waiting.
var errNoReply = noReplyError{}

type noReplyError struct{}

func (noReplyError) Error() string { return "no magic ping reply" }
func (noReplyError) Timeout() bool { return true }

// ReadMagicReply waits up to a second for the gateway's answer to a magic ping.
func (esp *ESP) ReadMagicReply() error {
	buffer := make([]byte, 1500)
	for {
		length, _, err := unix.Recvfrom(esp.icmp, buffer, 0)
		if errors.Is(err, unix.EAGAIN) {
			return errNoReply
		}
		// Go's runtime interrupts system calls with its own signals, such as for preemption.
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if tunnel.IsMagicReply(buffer[:length], esp.magic) {
			return nil
		}
	}
}

// RemoveLeftovers deletes the interface, policies and states a killed run left behind.
func RemoveLeftovers(name string, ifid uint32) error {
	var errs []error
	if link, err := netlink.LinkByName(name); err == nil {
		errs = append(errs, netlink.LinkDel(link))
	}
	policies, err := netlink.XfrmPolicyList(unix.AF_INET)
	errs = append(errs, err)
	for _, policy := range policies {
		if policy.Ifid == int(ifid) {
			errs = append(errs, netlink.XfrmPolicyDel(&policy))
		}
	}
	states, err := netlink.XfrmStateList(unix.AF_INET)
	errs = append(errs, err)
	for _, state := range states {
		if state.Ifid == int(ifid) {
			errs = append(errs, netlink.XfrmStateDel(&state))
		}
	}
	return errors.Join(errs...)
}

// Close removes everything OpenESP installed, in reverse order.
func (esp *ESP) Close() error {
	var errs []error
	if esp.icmp >= 0 {
		errs = append(errs, unix.Close(esp.icmp))
	}
	for _, policy := range esp.policies {
		errs = append(errs, netlink.XfrmPolicyDel(policy))
	}
	if esp.link != nil {
		errs = append(errs, netlink.LinkDel(esp.link))
	}
	for _, state := range esp.states {
		errs = append(errs, netlink.XfrmStateDel(state))
	}
	if esp.socket != nil {
		errs = append(errs, esp.socket.Close())
	}
	return errors.Join(errs...)
}
