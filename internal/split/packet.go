package split

import (
	"encoding/binary"
	"net"
	"time"
)

// Platforms that see the tunnel's IP packets, such as Android's VPN device, split by them:
// they cannot redirect DNS to a Forwarder, but every query to the tunnel's servers passes
// through them.

const (
	ipv4HeaderLength = 20
	udpHeaderLength  = 8
	protocolUDP      = 17
	dnsPort          = 53
)

// AnswerAddresses returns the A records, with their shortest TTL, of a DNS answer that packet,
// an IPv4 packet from the tunnel, carries from port 53, when its question matches domains.
func AnswerAddresses(packet []byte, domains Domains) ([]net.IP, time.Duration, bool) {
	payload, sourcePort, _, ok := udpPayload(packet)
	if !ok || sourcePort != dnsPort {
		return nil, 0, false
	}
	addresses, ttl, matched, err := matchedAddresses(payload, domains)
	return addresses, ttl, matched && err == nil
}

// IPv6Refusal returns the IPv4 packet answering, with no records, a query that packet, an IPv4
// packet bound for the tunnel, sends to port 53 for the AAAA records of a matching name.
func IPv6Refusal(packet []byte, domains Domains) ([]byte, bool) {
	query, sourcePort, destinationPort, ok := udpPayload(packet)
	if !ok || destinationPort != dnsPort {
		return nil, false
	}
	answer, blocked := withoutIPv6(query, domains)
	if !blocked {
		return nil, false
	}
	var source, destination [4]byte
	copy(source[:], packet[16:20])
	copy(destination[:], packet[12:16])
	return udpPacket(source, destination, dnsPort, sourcePort, answer), true
}

// udpPayload returns the payload and ports of an unfragmented IPv4 UDP packet.
func udpPayload(packet []byte) (payload []byte, sourcePort, destinationPort uint16, ok bool) {
	if len(packet) < ipv4HeaderLength || packet[0]>>4 != 4 || packet[9] != protocolUDP {
		return nil, 0, 0, false
	}
	// More fragments, or a fragment offset.
	if binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return nil, 0, 0, false
	}
	headerLength := int(packet[0]&0x0f) * 4
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerLength < ipv4HeaderLength || totalLength > len(packet) || totalLength < headerLength+udpHeaderLength {
		return nil, 0, 0, false
	}
	udp := packet[headerLength:totalLength]
	udpLength := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLength < udpHeaderLength || udpLength > len(udp) {
		return nil, 0, 0, false
	}
	return udp[udpHeaderLength:udpLength], binary.BigEndian.Uint16(udp[0:2]), binary.BigEndian.Uint16(udp[2:4]), true
}

// udpPacket builds an IPv4 UDP packet with valid checksums.
func udpPacket(source, destination [4]byte, sourcePort, destinationPort uint16, payload []byte) []byte {
	udpLength := udpHeaderLength + len(payload)
	packet := make([]byte, ipv4HeaderLength+udpLength)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocolUDP
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	binary.BigEndian.PutUint16(packet[10:12], ^checksum(0, packet[:ipv4HeaderLength]))

	udp := packet[ipv4HeaderLength:]
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLength))
	copy(udp[udpHeaderLength:], payload)
	// The pseudo-header: addresses, protocol and UDP length.
	sum := checksum(0, packet[12:20])
	sum = checksum(sum, []byte{0, protocolUDP, byte(udpLength >> 8), byte(udpLength)})
	sum = ^checksum(sum, udp)
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], sum)
	return packet
}

// checksum adds data to the ones' complement sum (RFC 1071).
func checksum(sum uint16, data []byte) uint16 {
	total := uint32(sum)
	for len(data) >= 2 {
		total += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) == 1 {
		total += uint32(data[0]) << 8
	}
	for total > 0xffff {
		total = total>>16 + total&0xffff
	}
	return uint16(total)
}
