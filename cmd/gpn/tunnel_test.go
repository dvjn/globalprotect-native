package main

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/split"
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
	if !needsRebuild(fmt.Errorf("%w: local address changed", errNetworkChanged)) || !needsRebuild(errRekeyDue) {
		t.Error("rekey and network change must rebuild at once")
	}
	if needsRebuild(errors.New("ESP tunnel dead")) || needsRebuild(nil) {
		t.Error("other failures must wait for the backoff")
	}
}

var testGatewayConfig = gp.GatewayConfig{
	ClientIP:       "10.9.0.2",
	GatewayAddress: "192.0.2.1",
	DNSServers:     []string{"10.0.0.53"},
	DNSSuffixes:    []string{"corp.example"},
	IncludeRoutes:  []string{"0.0.0.0/0"},
	ExcludeDomains: []string{"*.linkedin.com"},
}

func TestTrafficPlanExcludes(t *testing.T) {
	plan, err := newTrafficPlan("192.0.2.1", testGatewayConfig, config.Config{ExcludeDomains: []string{"fast.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.routing.IncludeOnly || plan.dns.Selective || plan.direction != split.Around ||
		plan.routing.ExcludeMark != split.Mark || plan.domains.Count() != 2 {
		t.Errorf("got %+v", plan)
	}
}

func TestTrafficPlanIncludeOnly(t *testing.T) {
	settings := config.Config{
		ExcludeDomains: []string{"fast.com"},
		IncludeDomains: []string{"*.corp.example"},
		IncludeRoutes:  []string{"172.16.0.0/12", " 198.51.100.7 "},
	}
	plan, err := newTrafficPlan("192.0.2.1", testGatewayConfig, settings)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.routing.IncludeOnly || plan.routing.ExcludeMark != 0 || plan.routing.OnlyMark != split.Mark || plan.direction != split.Through {
		t.Errorf("got %+v", plan.routing)
	}
	if got, want := joinPrefixes(plan.routing.OnlyRoutes), "172.16.0.0/12 198.51.100.7/32 10.0.0.53/32"; got != want {
		t.Errorf("only routes %q, want %q", got, want)
	}
	if got := joinPrefixes(plan.routing.IncludeRoutes); got != "0.0.0.0/0" {
		t.Errorf("tunnel table routes %q", got)
	}
	if plan.domains.Match("www.linkedin.com") || !plan.domains.Match("wiki.corp.example") {
		t.Error("include-only mode must match the include domains alone")
	}
	if !plan.dns.Selective || !slices.Equal(plan.dns.RoutingDomains, []string{"~corp.example"}) {
		t.Errorf("got DNS %+v", plan.dns)
	}
}

func TestParseIncludeRoutes(t *testing.T) {
	for _, bad := range []string{"10.0.0.0/33", "2001:db8::/32", "2001:db8::1", "vpn.example.com"} {
		if _, err := parseIncludeRoutes([]string{bad}); err == nil {
			t.Errorf("%q is accepted", bad)
		}
	}
}
