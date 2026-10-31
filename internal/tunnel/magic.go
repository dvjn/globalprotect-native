package tunnel

import (
	"encoding/binary"
	"net"
)

// magicPayload makes the gateway answer the ping that keeps ESP alive. See gpst.c in OpenConnect.
var magicPayload = []byte("monitor\x00\x00pan ha ")

const (
	protocolICMP     = 1
	icmpEchoReply    = 0
	icmpEchoRequest  = 8
	magicIdentifier  = 0x4747
	ipv4HeaderLength = 20
)

// MagicPing is the ICMP echo request that tells the gateway ESP is alive, without an IP header.
func MagicPing(sequence uint16) []byte {
	message := make([]byte, 8+len(magicPayload))
	message[0] = icmpEchoRequest
	binary.BigEndian.PutUint16(message[4:], magicIdentifier)
	binary.BigEndian.PutUint16(message[6:], sequence)
	copy(message[8:], magicPayload)
	binary.BigEndian.PutUint16(message[2:], internetChecksum(message))
	return message
}

// magicPingPacket is MagicPing in an IPv4 packet from source to magic.
func magicPingPacket(source, magic net.IP, sequence uint16) []byte {
	message := MagicPing(sequence)
	packet := make([]byte, ipv4HeaderLength+len(message))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocolICMP
	copy(packet[12:16], source.To4())
	copy(packet[16:20], magic.To4())
	binary.BigEndian.PutUint16(packet[10:], internetChecksum(packet[:ipv4HeaderLength]))
	copy(packet[ipv4HeaderLength:], message)
	return packet
}

// IsMagicReply checks for an IPv4 ICMP echo reply from magic that carries the magic payload.
func IsMagicReply(packet []byte, magic net.IP) bool {
	if len(packet) < ipv4HeaderLength || packet[0]>>4 != 4 || packet[9] != protocolICMP {
		return false
	}
	headerLength := int(packet[0]&0x0f) * 4
	if !net.IP(packet[12:16]).Equal(magic) || len(packet) < headerLength+8+len(magicPayload) {
		return false
	}
	icmp := packet[headerLength:]
	return icmp[0] == icmpEchoReply && string(icmp[8:8+len(magicPayload)]) == string(magicPayload)
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
