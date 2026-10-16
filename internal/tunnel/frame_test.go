package tunnel

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEncodeFrameIPv4(t *testing.T) {
	packet := []byte{0x45, 0x00, 0x00, 0x14}
	got := hex.EncodeToString(encodeFrame(packet))
	want := "1a2b3c4d" + "0800" + "0004" + "01000000" + "00000000" + "45000014"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestEncodeFrameIPv6(t *testing.T) {
	frame := encodeFrame([]byte{0x60, 0x00})
	if frame[4] != 0x86 || frame[5] != 0xdd {
		t.Errorf("ethertype = %x, want 86dd", frame[4:6])
	}
}

func TestReadFrameRoundTrip(t *testing.T) {
	packet := []byte{0x45, 1, 2, 3, 4, 5}
	stream := bytes.NewReader(append(keepaliveFrame(), encodeFrame(packet)...))
	buffer := make([]byte, 2048)

	keepalive, err := readFrame(stream, buffer)
	if err != nil || keepalive != nil {
		t.Fatalf("keepalive: got %v, %v; want nil, nil", keepalive, err)
	}
	got, err := readFrame(stream, buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, packet) {
		t.Errorf("got %x, want %x", got, packet)
	}
}

func TestReadFrameRejectsBadInput(t *testing.T) {
	badMagic := encodeFrame([]byte{0x45})
	badMagic[0] = 0
	tooLong := encodeFrame(make([]byte, 100))

	for name, test := range map[string]struct {
		frame  []byte
		buffer int
	}{
		"bad magic": {badMagic, 2048},
		"too long":  {tooLong, 64},
		"truncated": {encodeFrame([]byte{0x45, 1, 2})[:18], 2048},
	} {
		if _, err := readFrame(bytes.NewReader(test.frame), make([]byte, test.buffer)); err == nil {
			t.Errorf("%s: got no error", name)
		}
	}
}
