// Package tunnel carries IP packets to a GlobalProtect gateway over the SSL tunnel.
package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Every packet on the SSL tunnel starts with this 16-byte header:
// magic (big endian), ethertype (big endian), payload length (big endian),
// then 1 and 0 as little-endian 32-bit values. A keepalive is the magic followed by zeros.
// See gpst.c in OpenConnect.
const (
	headerSize    = 16
	frameMagic    = 0x1a2b3c4d
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
)

func encodeFrame(packet []byte) []byte {
	frame := make([]byte, headerSize+len(packet))
	binary.BigEndian.PutUint32(frame[0:], frameMagic)
	binary.BigEndian.PutUint16(frame[4:], etherType(packet))
	binary.BigEndian.PutUint16(frame[6:], uint16(len(packet)))
	binary.LittleEndian.PutUint32(frame[8:], 1)
	copy(frame[headerSize:], packet)
	return frame
}

func keepaliveFrame() []byte {
	frame := make([]byte, headerSize)
	binary.BigEndian.PutUint32(frame, frameMagic)
	return frame
}

func etherType(packet []byte) uint16 {
	if len(packet) > 0 && packet[0]>>4 == 6 {
		return etherTypeIPv6
	}
	return etherTypeIPv4
}

// readFrame reads one frame into buffer and returns its IP packet, or nil for a keepalive.
func readFrame(reader io.Reader, buffer []byte) ([]byte, error) {
	header := buffer[:headerSize]
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if magic := binary.BigEndian.Uint32(header); magic != frameMagic {
		return nil, fmt.Errorf("bad frame magic %#x", magic)
	}

	length := int(binary.BigEndian.Uint16(header[6:]))
	switch binary.BigEndian.Uint16(header[4:]) {
	case 0:
		return nil, nil
	case etherTypeIPv4, etherTypeIPv6:
	default:
		return nil, fmt.Errorf("unknown frame type %#x", binary.BigEndian.Uint16(header[4:]))
	}
	if length > len(buffer) {
		return nil, fmt.Errorf("frame of %d bytes exceeds the %d-byte buffer", length, len(buffer))
	}

	packet := buffer[:length]
	if _, err := io.ReadFull(reader, packet); err != nil {
		return nil, err
	}
	return packet, nil
}
