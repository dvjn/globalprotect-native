package engine

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/gp"
)

func TestRekeyInterval(t *testing.T) {
	tests := map[int]time.Duration{
		10800: 3*time.Hour - time.Minute,
		0:     0,
		60:    0,
		121:   61 * time.Second,
	}
	for timeout, want := range tests {
		if got := rekeyInterval(timeout); got != want {
			t.Errorf("rekeyInterval(%d) = %s, want %s", timeout, got, want)
		}
	}
}

func TestNeedsRebuild(t *testing.T) {
	if !NeedsRebuild(fmt.Errorf("%w: local address changed", errNetworkChanged)) || !NeedsRebuild(errRekeyDue) {
		t.Error("rekey and network change must rebuild at once")
	}
	if NeedsRebuild(errors.New("ESP tunnel dead")) || NeedsRebuild(nil) {
		t.Error("other failures must wait for the backoff")
	}
}

type timeoutError struct{}

func (timeoutError) Error() string { return "no reply" }
func (timeoutError) Timeout() bool { return true }

func TestIsTimeout(t *testing.T) {
	if !isTimeout(fmt.Errorf("read: %w", timeoutError{})) || isTimeout(errors.New("closed")) || isTimeout(nil) {
		t.Error("isTimeout must recognise wrapped timeouts only")
	}
}

// testGatewayConfig uses an address as the gateway host, so NewNetwork resolves it offline.
var testGatewayConfig = gp.GatewayConfig{
	ClientIP:       "10.9.0.2",
	GatewayAddress: "192.0.2.1",
	DNSServers:     []string{"10.0.0.53"},
	DNSSuffixes:    []string{"corp.example"},
	IncludeRoutes:  []string{"0.0.0.0/0"},
	ExcludeDomains: []string{"*.linkedin.com"},
}

func TestNetworkExcludes(t *testing.T) {
	network, err := NewNetwork("192.0.2.1", testGatewayConfig, config.Config{ExcludeDomains: []string{"fast.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if network.IncludeOnly || network.Domains.Count() != 2 || network.MTU != defaultMTU {
		t.Errorf("got %+v", network)
	}
	if got := JoinPrefixes(network.Routes); got != "0.0.0.0/0" {
		t.Errorf("routes %q", got)
	}
	if !network.Gateway.Equal(network.Gateways[0]) || len(network.Gateways) != 1 {
		t.Errorf("gateways %v, gateway %v", network.Gateways, network.Gateway)
	}
}

func TestNetworkIncludeOnly(t *testing.T) {
	settings := config.Config{
		ExcludeDomains: []string{"fast.com"},
		IncludeDomains: []string{"*.corp.example"},
		IncludeRoutes:  []string{"172.16.0.0/12", " 198.51.100.7 "},
	}
	network, err := NewNetwork("192.0.2.1", testGatewayConfig, settings)
	if err != nil {
		t.Fatal(err)
	}
	if !network.IncludeOnly {
		t.Errorf("got %+v", network)
	}
	if got, want := JoinPrefixes(network.Routes), "172.16.0.0/12 198.51.100.7/32 10.0.0.53/32"; got != want {
		t.Errorf("routes %q, want %q", got, want)
	}
	if network.Domains.Match("www.linkedin.com") || !network.Domains.Match("wiki.corp.example") {
		t.Error("include-only mode must match the include domains alone")
	}
}

func TestParseIncludeRoutes(t *testing.T) {
	for _, bad := range []string{"10.0.0.0/33", "2001:db8::/32", "2001:db8::1", "vpn.example.com"} {
		if _, err := parseIncludeRoutes([]string{bad}); err == nil {
			t.Errorf("%q is accepted", bad)
		}
	}
}
