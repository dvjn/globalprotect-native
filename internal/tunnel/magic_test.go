package tunnel

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestInternetChecksum(t *testing.T) {
	// The example from RFC 1071, section 3.
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	if got := internetChecksum(data); got != ^uint16(0xddf2) {
		t.Errorf("got %#04x, want %#04x", got, ^uint16(0xddf2))
	}
	withChecksum := append([]byte{}, data...)
	withChecksum = binary.BigEndian.AppendUint16(withChecksum, internetChecksum(data))
	if internetChecksum(withChecksum) != 0 {
		t.Error("a message carrying its checksum does not sum to zero")
	}
}

func magicReply(source net.IP, icmpType byte, payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	packet[9] = 1
	copy(packet[12:16], source.To4())
	packet[20] = icmpType
	copy(packet[28:], payload)
	return packet
}

func TestIsMagicReply(t *testing.T) {
	gateway := net.ParseIP("203.0.113.10")
	tests := []struct {
		name   string
		packet []byte
		want   bool
	}{
		{"reply", magicReply(gateway, 0, magicPayload), true},
		{"echo request", magicReply(gateway, 8, magicPayload), false},
		{"other source", magicReply(net.ParseIP("198.51.100.1"), 0, magicPayload), false},
		{"other payload", magicReply(gateway, 0, []byte("ordinary ping   ")), false},
		{"short", magicReply(gateway, 0, magicPayload)[:30], false},
	}
	for _, test := range tests {
		if got := IsMagicReply(test.packet, gateway); got != test.want {
			t.Errorf("%s: got %t, want %t", test.name, got, test.want)
		}
	}
}

func TestMagicPingPacketIsValidIPv4(t *testing.T) {
	packet := magicPingPacket(net.ParseIP("10.0.0.2"), net.ParseIP("203.0.113.10"), 7)
	if internetChecksum(packet[:ipv4HeaderLength]) != 0 || internetChecksum(packet[ipv4HeaderLength:]) != 0 {
		t.Error("bad IP or ICMP checksum")
	}
	if int(binary.BigEndian.Uint16(packet[2:])) != len(packet) || binary.BigEndian.Uint16(packet[ipv4HeaderLength+6:]) != 7 {
		t.Errorf("bad length or sequence: % x", packet)
	}
}
