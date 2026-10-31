package xfrm

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/dvjn/globalprotect-native/internal/gp"
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
		if got := isMagicReply(test.packet, gateway); got != test.want {
			t.Errorf("%s: got %t, want %t", test.name, got, test.want)
		}
	}
}

func TestSetAlgorithms(t *testing.T) {
	keys := gp.ESPKeys{EncryptionKey: make([]byte, 36), IntegrityKey: make([]byte, 20)}

	var gcm netlink.XfrmState
	if err := setAlgorithms(&gcm, gp.ESPConfig{Encryption: "aes-256-gcm", Integrity: "sha1"}, keys); err != nil {
		t.Fatal(err)
	}
	if gcm.Aead == nil || gcm.Aead.Name != "rfc4106(gcm(aes))" || gcm.Aead.ICVLen != 128 || gcm.Auth != nil {
		t.Errorf("GCM: got aead %+v, auth %+v", gcm.Aead, gcm.Auth)
	}

	var cbc netlink.XfrmState
	if err := setAlgorithms(&cbc, gp.ESPConfig{Encryption: "aes-128-cbc", Integrity: "sha1"}, keys); err != nil {
		t.Fatal(err)
	}
	if cbc.Crypt == nil || cbc.Crypt.Name != "cbc(aes)" || cbc.Auth == nil || cbc.Auth.TruncateLen != 96 {
		t.Errorf("CBC: got crypt %+v, auth %+v", cbc.Crypt, cbc.Auth)
	}

	if err := setAlgorithms(&netlink.XfrmState{}, gp.ESPConfig{Encryption: "des"}, keys); err == nil {
		t.Error("accepted an unsupported cipher")
	}
}
