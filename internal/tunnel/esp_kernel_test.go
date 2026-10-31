//go:build linux

package tunnel

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/dvjn/globalprotect-native/internal/gp"
)

// TestESPAgainstKernel checks the ESP wire format against the kernel's: in a network namespace
// of its own, the kernel plays the gateway, decrypting the magic ping, answering it like any
// ping and encrypting the reply. It needs unprivileged user namespaces and iproute2.
func TestESPAgainstKernel(t *testing.T) {
	if os.Getenv("GPN_TEST_NETNS") == "" {
		unshare, err := exec.LookPath("unshare")
		if err != nil {
			t.Skip("no unshare")
		}
		if exec.Command(unshare, "-Urn", "true").Run() != nil {
			t.Skip("unprivileged user namespaces are not available")
		}
		command := exec.Command(unshare, "-Urn", os.Args[0], "-test.run=^TestESPAgainstKernel$", "-test.v")
		command.Env = append(os.Environ(), "GPN_TEST_NETNS=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, output)
		}
		if strings.Contains(string(output), "--- SKIP") {
			t.Skipf("%s", output)
		}
		return
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("no iproute2")
	}

	const (
		gatewayOuter, clientOuter = "127.0.0.1", "127.0.0.2"
		gatewayPort               = 4500
	)
	gatewayInner, clientInner := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	ip(t, "link", "set", "lo", "up")
	ip(t, "addr", "add", gatewayInner.String()+"/32", "dev", "lo")
	// Linux never encrypts what leaves through loopback, so the replies take a dummy device.
	ip(t, "link", "add", "esp0", "type", "dummy")
	ip(t, "link", "set", "esp0", "up")
	ip(t, "route", "add", clientInner.String()+"/32", "dev", "esp0")
	ip(t, "xfrm", "policy", "add", "dir", "out", "src", "0.0.0.0/0", "dst", clientInner.String()+"/32",
		"tmpl", "src", gatewayOuter, "dst", clientOuter, "proto", "esp", "mode", "tunnel")
	ip(t, "xfrm", "policy", "add", "dir", "in", "src", clientInner.String()+"/32", "dst", "0.0.0.0/0",
		"tmpl", "src", clientOuter, "dst", gatewayOuter, "proto", "esp", "mode", "tunnel")
	encapSocket := gatewayEncapSocket(t, gatewayOuter, gatewayPort)
	defer unix.Close(encapSocket)

	for _, suite := range cipherSuites {
		config := testESPConfig(suite[0], suite[1])
		connection, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(clientOuter)},
			&net.UDPAddr{IP: net.ParseIP(gatewayOuter), Port: gatewayPort})
		if err != nil {
			t.Fatal(err)
		}
		clientPort := connection.LocalAddr().(*net.UDPAddr).Port
		ip(t, append([]string{"xfrm", "state", "add", "src", clientOuter, "dst", gatewayOuter},
			kernelState(config, config.ClientToServer.SPI, config.ClientToServer.EncryptionKey, config.ClientToServer.IntegrityKey, clientPort, gatewayPort)...)...)
		ip(t, append([]string{"xfrm", "state", "add", "src", gatewayOuter, "dst", clientOuter},
			kernelState(config, config.ServerToClient.SPI, config.ServerToClient.EncryptionKey, config.ServerToClient.IntegrityKey, gatewayPort, clientPort)...)...)

		esp, err := NewESP(connection, config, clientInner, gatewayInner)
		if err != nil {
			t.Fatal(err)
		}
		if err := esp.Probe(3 * time.Second); err != nil {
			t.Errorf("%v: the kernel did not answer: %v", suite, err)
		}
		esp.Close()
		ip(t, "xfrm", "state", "flush")
	}
}

func ip(t *testing.T, arguments ...string) {
	t.Helper()
	if output, err := exec.Command("ip", arguments...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(arguments, " "), err, output)
	}
}

// kernelState is the `ip xfrm state add` arguments after the addresses for one direction.
func kernelState(config gp.ESPConfig, spi uint32, encryptionKey, integrityKey []byte, sourcePort, destinationPort int) []string {
	arguments := []string{"proto", "esp", "spi", fmt.Sprintf("%#x", spi), "mode", "tunnel", "replay-window", "32"}
	if strings.HasSuffix(config.Encryption, "gcm") {
		arguments = append(arguments, "aead", "rfc4106(gcm(aes))", fmt.Sprintf("0x%x", encryptionKey), "128")
	} else {
		hash, truncation := map[string]string{"sha1": "sha1", "sha256": "sha256", "md5": "md5"}[config.Integrity], 96
		if config.Integrity == "sha256" {
			truncation = 128
		}
		arguments = append(arguments, "enc", "cbc(aes)", fmt.Sprintf("0x%x", encryptionKey),
			"auth-trunc", "hmac("+hash+")", fmt.Sprintf("0x%x", integrityKey), fmt.Sprint(truncation))
	}
	return append(arguments, "encap", "espinudp", fmt.Sprint(sourcePort), fmt.Sprint(destinationPort), "0.0.0.0")
}

// gatewayEncapSocket opens the UDP socket the kernel decapsulates the client's ESP on.
func gatewayEncapSocket(t *testing.T, address string, port int) int {
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	bound := &unix.SockaddrInet4{Port: port}
	copy(bound.Addr[:], net.ParseIP(address).To4())
	if err := unix.Bind(socket, bound); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptInt(socket, unix.IPPROTO_UDP, unix.UDP_ENCAP, unix.UDP_ENCAP_ESPINUDP); err != nil {
		t.Fatal(err)
	}
	return socket
}
