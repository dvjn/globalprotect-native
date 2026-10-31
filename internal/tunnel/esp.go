package tunnel

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/dvjn/globalprotect-native/internal/gp"
)

// ESP carries IP packets to the gateway as ESP in UDP (RFC 3948), encrypting them itself, for
// systems whose kernel cannot.
type ESP struct {
	connection net.Conn
	outbound   *sa
	inbound    *sa
	clientIP   net.IP
	magic      net.IP

	writeLock     sync.Mutex
	sequence      uint32
	pingSequence  uint16
	replay        replayWindow
	receiveBuffer []byte
}

// NewESP runs ESP with the gateway's keys over connection, a UDP socket connected to the
// gateway's ESP port. clientIP is the tunnel's address and gateway the target of the magic ping.
func NewESP(connection net.Conn, config gp.ESPConfig, clientIP, gateway net.IP) (*ESP, error) {
	outbound, err := newSA(config, config.ClientToServer)
	if err != nil {
		return nil, err
	}
	inbound, err := newSA(config, config.ServerToClient)
	if err != nil {
		return nil, err
	}
	return &ESP{
		connection:    connection,
		outbound:      outbound,
		inbound:       inbound,
		clientIP:      clientIP,
		magic:         gateway,
		receiveBuffer: make([]byte, 64<<10),
	}, nil
}

// WritePacket encrypts and sends one IP packet.
func (esp *ESP) WritePacket(packet []byte) error {
	nextHeader := byte(nextHeaderIPv4)
	if len(packet) > 0 && packet[0]>>4 == 6 {
		nextHeader = nextHeaderIPv6
	}
	esp.writeLock.Lock()
	defer esp.writeLock.Unlock()
	esp.sequence++
	sealed, err := esp.outbound.seal(esp.sequence, packet, nextHeader)
	if err != nil {
		return err
	}
	_, err = esp.connection.Write(sealed)
	return err
}

// SendKeepalive sends the magic ping, which the gateway answers to show ESP is alive.
func (esp *ESP) SendKeepalive() error {
	esp.writeLock.Lock()
	esp.pingSequence++
	sequence := esp.pingSequence
	esp.writeLock.Unlock()
	return esp.WritePacket(magicPingPacket(esp.clientIP, esp.magic, sequence))
}

// ReadPacket returns the next IP packet from the gateway, or nil for the reply to a magic ping.
// It drops what fails authentication, replays and what is not ESP. The packet is only valid
// until the next call.
func (esp *ESP) ReadPacket() ([]byte, error) {
	for {
		packet, magic, err := esp.receive()
		if err != nil {
			return nil, err
		}
		if magic {
			return nil, nil
		}
		if packet != nil {
			return packet, nil
		}
	}
}

// receive reads one datagram and returns the IP packet it carries, or whether it is the reply
// to a magic ping. A datagram that carries neither returns nothing.
func (esp *ESP) receive() (packet []byte, magic bool, err error) {
	length, err := esp.connection.Read(esp.receiveBuffer)
	if err != nil {
		return nil, false, err
	}
	datagram := esp.receiveBuffer[:length]
	// A single 0xff byte is a NAT keepalive; a zero SPI marks IKE, which gpn does not speak.
	if length == 1 || length >= 4 && datagram[0]|datagram[1]|datagram[2]|datagram[3] == 0 {
		return nil, false, nil
	}

	sequence, payload, nextHeader, err := esp.inbound.open(datagram)
	if err != nil || !esp.replay.fresh(sequence) {
		return nil, false, nil
	}
	esp.replay.accept(sequence)
	switch {
	case nextHeader == nextHeaderNone:
		return nil, false, nil
	case IsMagicReply(payload, esp.magic):
		return nil, true, nil
	}
	return payload, false, nil
}

// Probe sends magic pings until the gateway answers one, or gives up after timeout. Packets
// that arrive meanwhile are dropped: nothing routes into the tunnel yet.
func (esp *ESP) Probe(timeout time.Duration) error {
	defer esp.connection.SetReadDeadline(time.Time{})
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := esp.SendKeepalive(); err != nil {
			return err
		}
		wait := time.Now().Add(time.Second)
		if wait.After(deadline) {
			wait = deadline
		}
		esp.connection.SetReadDeadline(wait)
		for {
			_, magic, err := esp.receive()
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				break
			}
			if err != nil {
				return err
			}
			if magic {
				return nil
			}
		}
	}
	return fmt.Errorf("no magic ping reply within %s", timeout)
}

// Close closes the UDP socket.
func (esp *ESP) Close() error {
	return esp.connection.Close()
}
