package mobile

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/engine"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"golang.org/x/net/dns/dnsmessage"
)

// vpnApp hands out one end of a socket pair for each Establish, and keeps the other as the
// system's side of the VPN device.
type vpnApp struct {
	fakeApp
	lock    sync.Mutex
	configs []TunnelConfig
	peers   []*os.File
}

func (app *vpnApp) Establish(config *TunnelConfig) (int, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return -1, err
	}
	app.lock.Lock()
	defer app.lock.Unlock()
	app.configs = append(app.configs, *config)
	app.peers = append(app.peers, os.NewFile(uintptr(fds[1]), "peer"))
	return fds[0], nil
}

func (app *vpnApp) peer(t *testing.T) *os.File {
	t.Helper()
	app.lock.Lock()
	defer app.lock.Unlock()
	peer := app.peers[len(app.peers)-1]
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	return peer
}

// dnsPacket is an IPv4 UDP packet with DNS message, without checksums.
func dnsPacket(t *testing.T, fromServer bool, header dnsmessage.Header, question dnsmessage.Question, answers ...[4]byte) []byte {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, header)
	builder.StartQuestions()
	builder.Question(question)
	builder.StartAnswers()
	for _, address := range answers {
		builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: address})
	}
	message, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 28+len(message))
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	server, client := []byte{10, 0, 0, 53}, []byte{10, 9, 0, 2}
	ports := []uint16{40000, 53}
	if fromServer {
		server, client = client, server
		ports[0], ports[1] = 53, 40000
	}
	copy(packet[12:16], client)
	copy(packet[16:20], server)
	binary.BigEndian.PutUint16(packet[20:22], ports[0])
	binary.BigEndian.PutUint16(packet[22:24], ports[1])
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(message)))
	copy(packet[28:], message)
	return packet
}

func TestSplitDeviceRoutesIncludeDomains(t *testing.T) {
	settings := config.Config{IncludeDomains: []string{"*.corp.example"}}
	network, err := engine.NewNetwork(context.Background(), net.DefaultResolver, "192.0.2.1", gp.GatewayConfig{
		ClientIP: "10.9.0.2", GatewayAddress: "192.0.2.1", DNSServers: []string{"10.0.0.53"},
	}, settings)
	if err != nil {
		t.Fatal(err)
	}
	app := &vpnApp{}
	device, err := newPlatform(app).Establish(network)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()

	name := dnsmessage.MustNewName("wiki.corp.example.")
	answer := dnsPacket(t, true, dnsmessage.Header{ID: 1, Response: true},
		dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, [4]byte{10, 7, 7, 7})
	if _, err := device.Write(answer); err != nil {
		t.Fatal(err)
	}
	if len(app.configs) != 2 || app.configs[1].Routes != "10.0.0.53/32,10.7.7.7/32" {
		t.Fatalf("established %+v", app.configs)
	}
	// The answer reaches the app on the new device, and the same answer again changes nothing.
	buffer := make([]byte, 1500)
	if length, err := app.peer(t).Read(buffer); err != nil || length != len(answer) {
		t.Fatalf("the app got %d bytes, %v", length, err)
	}
	device.Write(answer)
	if len(app.configs) != 2 {
		t.Errorf("established again for a known address: %+v", app.configs[2:])
	}

	// An AAAA query for an include domain is answered on the device; others go to the gateway.
	read := make(chan []byte, 1)
	go func() {
		packet := make([]byte, 1500)
		length, err := device.Read(packet)
		if err != nil {
			t.Error(err)
		}
		read <- packet[:length]
	}()
	app.peer(t).Write(dnsPacket(t, false, dnsmessage.Header{ID: 2},
		dnsmessage.Question{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}))
	if length, err := app.peer(t).Read(buffer); err != nil || binary.BigEndian.Uint16(buffer[20:22]) != 53 {
		t.Fatalf("got %d bytes, %v, for the AAAA query", length, err)
	}
	other := dnsPacket(t, false, dnsmessage.Header{ID: 3},
		dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET})
	app.peer(t).Write(other)
	select {
	case packet := <-read:
		if len(packet) != len(other) {
			t.Errorf("the gateway got %d bytes, want %d", len(packet), len(other))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the other query never left for the gateway")
	}
}

func TestSplitDeviceExcludesDomains(t *testing.T) {
	network, err := engine.NewNetwork(context.Background(), net.DefaultResolver, "192.0.2.1", gp.GatewayConfig{
		ClientIP: "10.9.0.2", GatewayAddress: "192.0.2.1", DNSServers: []string{"10.0.0.53"},
		IncludeRoutes: []string{"0.0.0.0/0"}, ExcludeDomains: []string{"fast.com"},
	}, config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	app := &vpnApp{}
	device, err := newPlatform(app).Establish(network)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()

	device.Write(dnsPacket(t, true, dnsmessage.Header{ID: 1, Response: true},
		dnsmessage.Question{Name: dnsmessage.MustNewName("fast.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		[4]byte{198, 51, 100, 1}, [4]byte{198, 51, 100, 2}))
	if len(app.configs) != 2 || !strings.Contains(app.configs[1].ExcludeRoutes, "198.51.100.1/32") ||
		!strings.Contains(app.configs[1].ExcludeRoutes, "198.51.100.2/32") || app.configs[1].Routes != "0.0.0.0/0" {
		t.Errorf("established %+v", app.configs)
	}
}
