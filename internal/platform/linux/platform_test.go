package linux

import (
	"context"
	"net"
	"slices"
	"testing"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/engine"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/split"
)

var testGatewayConfig = gp.GatewayConfig{
	ClientIP:       "10.9.0.2",
	GatewayAddress: "192.0.2.1",
	DNSServers:     []string{"10.0.0.53"},
	DNSSuffixes:    []string{"corp.example"},
	IncludeRoutes:  []string{"0.0.0.0/0"},
	ExcludeDomains: []string{"*.linkedin.com"},
}

func TestLinuxPlanExcludes(t *testing.T) {
	network, err := engine.NewNetwork(context.Background(), net.DefaultResolver, "192.0.2.1", testGatewayConfig, config.Config{ExcludeDomains: []string{"fast.com"}})
	if err != nil {
		t.Fatal(err)
	}
	plan, settings := routingPlan(network), dnsSettings(network)
	if plan.IncludeOnly || settings.Selective || splitDirection(network) != split.Around || plan.ExcludeMark != splitMark {
		t.Errorf("got %+v, %+v", plan, settings)
	}
	if got := engine.JoinPrefixes(plan.IncludeRoutes); got != "0.0.0.0/0" {
		t.Errorf("tunnel table routes %q", got)
	}
}

func TestLinuxPlanIncludeOnly(t *testing.T) {
	settings := config.Config{
		IncludeDomains: []string{"*.corp.example"},
		IncludeRoutes:  []string{"172.16.0.0/12"},
	}
	network, err := engine.NewNetwork(context.Background(), net.DefaultResolver, "192.0.2.1", testGatewayConfig, settings)
	if err != nil {
		t.Fatal(err)
	}
	plan := routingPlan(network)
	if !plan.IncludeOnly || plan.ExcludeMark != 0 || plan.OnlyMark != splitMark || splitDirection(network) != split.Through {
		t.Errorf("got %+v", plan)
	}
	if got, want := engine.JoinPrefixes(plan.OnlyRoutes), "172.16.0.0/12 10.0.0.53/32"; got != want {
		t.Errorf("only routes %q, want %q", got, want)
	}
	if got := engine.JoinPrefixes(plan.IncludeRoutes); got != "0.0.0.0/0" {
		t.Errorf("tunnel table routes %q", got)
	}
	resolved := dnsSettings(network)
	if !resolved.Selective || !slices.Equal(resolved.RoutingDomains, []string{"~corp.example"}) {
		t.Errorf("got DNS %+v", resolved)
	}
}
