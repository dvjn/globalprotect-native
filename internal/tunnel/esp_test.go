package tunnel

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/dvjn/globalprotect-native/internal/gp"
)

func testESPConfig(encryption, integrity string) gp.ESPConfig {
	keyLength := map[string]int{"aes-128-cbc": 16, "aes-256-cbc": 32, "aes-128-gcm": 20, "aes-256-gcm": 36}[encryption]
	keys := func(spi uint32, seed byte) gp.ESPKeys {
		return gp.ESPKeys{
			SPI:           spi,
			EncryptionKey: bytes.Repeat([]byte{seed}, keyLength),
			IntegrityKey:  bytes.Repeat([]byte{seed + 1}, 32),
		}
	}
	return gp.ESPConfig{
		Encryption:     encryption,
		Integrity:      integrity,
		ClientToServer: keys(0x1001, 0x11),
		ServerToClient: keys(0x2002, 0x22),
	}
}

var cipherSuites = [][2]string{
	{"aes-128-cbc", "sha1"},
	{"aes-256-cbc", "sha256"},
	{"aes-128-cbc", "md5"},
	{"aes-128-gcm", ""},
	{"aes-256-gcm", ""},
}

func TestSARoundTrip(t *testing.T) {
	for _, suite := range cipherSuites {
		config := testESPConfig(suite[0], suite[1])
		association, err := newSA(config, config.ClientToServer)
		if err != nil {
			t.Fatalf("%v: %v", suite, err)
		}
		for _, length := range []int{0, 1, 13, 14, 15, 16, 1279} {
			payload := bytes.Repeat([]byte{0xab}, length)
			packet, err := association.seal(42, payload, nextHeaderIPv4)
			if err != nil {
				t.Fatal(err)
			}
			if association.gcm == nil && (len(packet)-espHeaderLength-16-association.icvLength)%16 != 0 {
				t.Errorf("%v: ciphertext of %d bytes is not whole blocks", suite, len(packet))
			}
			sequence, opened, nextHeader, err := association.open(packet)
			if err != nil || sequence != 42 || nextHeader != nextHeaderIPv4 || !bytes.Equal(opened, payload) {
				t.Errorf("%v, %d bytes: got %d %d %x %v", suite, length, sequence, nextHeader, opened, err)
			}

			packet[len(packet)-1] ^= 1
			if _, _, _, err := association.open(packet); !errors.Is(err, errAuthentication) {
				t.Errorf("%v: a tampered packet gave %v", suite, err)
			}
		}
	}
}

func TestSARejectsOtherSPI(t *testing.T) {
	config := testESPConfig("aes-128-gcm", "")
	outbound, _ := newSA(config, config.ClientToServer)
	inbound, _ := newSA(config, config.ServerToClient)
	packet, _ := outbound.seal(1, []byte("hello"), nextHeaderIPv4)
	if _, _, _, err := inbound.open(packet); err == nil {
		t.Error("opened a packet for another SPI")
	}
}

func TestReplayWindow(t *testing.T) {
	var window replayWindow
	for _, step := range []struct {
		sequence uint32
		fresh    bool
	}{
		{0, false}, {1, true}, {1, false}, {3, true}, {2, true}, {2, false},
		{100, true}, {37, true}, {36, false}, {99, true}, {100, false},
	} {
		if got := window.fresh(step.sequence); got != step.fresh {
			t.Errorf("sequence %d: fresh %t, want %t", step.sequence, got, step.fresh)
		}
		if step.fresh {
			window.accept(step.sequence)
		}
	}
}

// gatewayESP is the gateway's end of the ESP tunnel: the keys of the other direction.
func gatewayESP(t *testing.T, config gp.ESPConfig, connection net.Conn, clientIP, gateway net.IP) *ESP {
	config.ClientToServer, config.ServerToClient = config.ServerToClient, config.ClientToServer
	esp, err := NewESP(connection, config, gateway, clientIP)
	if err != nil {
		t.Fatal(err)
	}
	return esp
}

// replyingTo is a gateway's UDP socket that answers the client it last heard from, as through NAT.
type replyingTo struct {
	*net.UDPConn
	client *net.UDPAddr
}

func (socket *replyingTo) Read(buffer []byte) (int, error) {
	length, client, err := socket.ReadFromUDP(buffer)
	socket.client = client
	return length, err
}

func (socket *replyingTo) Write(datagram []byte) (int, error) {
	return socket.WriteToUDP(datagram, socket.client)
}

// serveGateway answers magic pings and echoes every other packet back, as a loopback host
// behind the gateway would.
func serveGateway(esp *ESP, gateway, clientIP net.IP) {
	for {
		packet, err := esp.ReadPacket()
		if err != nil {
			return
		}
		if len(packet) >= ipv4HeaderLength+8 && packet[9] == protocolICMP && packet[ipv4HeaderLength] == icmpEchoRequest {
			reply := magicPingPacket(gateway, clientIP, 0)
			reply[ipv4HeaderLength] = icmpEchoReply
			esp.WritePacket(reply)
			continue
		}
		esp.WritePacket(append([]byte{}, packet...))
	}
}

func TestESPOverUDP(t *testing.T) {
	clientIP, gatewayIP := net.ParseIP("10.0.0.2"), net.ParseIP("203.0.113.10")
	data := append([]byte{0x45, 0, 0, 24, 0, 0, 0, 0, 64, 17}, make([]byte, 14)...)
	for _, suite := range cipherSuites {
		config := testESPConfig(suite[0], suite[1])
		gatewaySocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		clientSocket, err := net.DialUDP("udp4", nil, gatewaySocket.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		client, err := NewESP(clientSocket, config, clientIP, gatewayIP)
		if err != nil {
			t.Fatal(err)
		}
		gateway := gatewayESP(t, config, &replyingTo{UDPConn: gatewaySocket}, clientIP, gatewayIP)
		go serveGateway(gateway, gatewayIP, clientIP)

		if err := client.Probe(3 * time.Second); err != nil {
			t.Errorf("%v: probe: %v", suite, err)
		}
		if err := client.WritePacket(data); err != nil {
			t.Fatal(err)
		}
		clientSocket.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			packet, err := client.ReadPacket()
			if err != nil {
				t.Errorf("%v: no echo: %v", suite, err)
				break
			}
			if packet != nil {
				if !bytes.Equal(packet, data) {
					t.Errorf("%v: echo %x, want %x", suite, packet, data)
				}
				break
			}
		}
		client.Close()
		gateway.Close()
	}
}
