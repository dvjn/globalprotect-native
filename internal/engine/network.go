package engine

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/split"
)

const defaultMTU = 1280

// Network is how traffic and DNS flow while the tunnel is up.
type Network struct {
	ClientIP net.IP
	MTU      int
	// Gateway is the address ESP and the magic ping go to. Gateways are all of the gateway's
	// public addresses; traffic to them stays outside the tunnel, or the tunnel would carry
	// itself.
	Gateway  net.IP
	Gateways []net.IP
	// Routes go through the tunnel, except for ExcludeRoutes.
	Routes        []*net.IPNet
	ExcludeRoutes []*net.IPNet
	// LocalNetworkAccess keeps the system's specific routes, such as the LAN, ahead of the
	// tunnel.
	LocalNetworkAccess bool
	DNSServers         []string
	DNSSuffixes        []string
	// IncludeOnly sends only Routes and Domains through the tunnel, and resolves only Domains
	// and DNSSuffixes with DNSServers; everything else stays outside it. Routes then hold the
	// DNS servers as well. LocalNetworkAccess does not apply.
	IncludeOnly bool
	// Domains leave outside the tunnel or, with IncludeOnly, alone go through it.
	Domains split.Domains
}

// NewNetwork plans the network for the gateway's configuration and the user's settings. It
// resolves the gateway's addresses with resolver, so it has to run before the tunnel takes
// over DNS.
func NewNetwork(ctx context.Context, resolver *net.Resolver, gatewayHost string, gatewayConfig gp.GatewayConfig, settings config.Config) (Network, error) {
	gateways, err := gatewayAddresses(ctx, resolver, gatewayHost, gatewayConfig.GatewayAddress)
	if err != nil {
		return Network{}, err
	}
	routes, err := parseCIDRs(gatewayConfig.IncludeRoutes)
	if err != nil {
		return Network{}, err
	}
	excludeRoutes, err := parseCIDRs(gatewayConfig.ExcludeRoutes)
	if err != nil {
		return Network{}, err
	}
	mtu := gatewayConfig.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	network := Network{
		ClientIP:           net.ParseIP(gatewayConfig.ClientIP),
		MTU:                mtu,
		Gateway:            net.ParseIP(gatewayConfig.GatewayAddress),
		Gateways:           gateways,
		Routes:             routes,
		ExcludeRoutes:      excludeRoutes,
		LocalNetworkAccess: gatewayConfig.LocalNetworkAccess,
		DNSServers:         gatewayConfig.DNSServers,
		DNSSuffixes:        gatewayConfig.DNSSuffixes,
	}
	if settings.IncludeOnly() {
		return network.includeOnly(settings)
	}
	network.Domains = split.NewDomains(append(gatewayConfig.ExcludeDomains, settings.ExcludeDomains...))
	return network, nil
}

// includeOnly limits the tunnel to the configured routes and domains, and to the tunnel's DNS
// servers, which answer for the domains and the gateway's DNS suffixes. Every other name is
// resolved, and every other address reached, outside the tunnel.
func (network Network) includeOnly(settings config.Config) (Network, error) {
	routes, err := parseIncludeRoutes(settings.IncludeRoutes)
	if err != nil {
		return Network{}, err
	}
	for _, server := range network.DNSServers {
		if address := net.ParseIP(server).To4(); address != nil {
			routes = append(routes, &net.IPNet{IP: address, Mask: net.CIDRMask(32, 32)})
		}
	}
	network.IncludeOnly = true
	network.Routes = routes
	network.Domains = split.NewDomains(settings.IncludeDomains)
	return network, nil
}

func (network Network) String() string {
	if network.IncludeOnly {
		return fmt.Sprintf("include only: routes %s, %d include domains, DNS %s",
			JoinPrefixes(network.Routes), network.Domains.Count(), strings.Join(network.DNSServers, " "))
	}
	return fmt.Sprintf("routes %s, DNS %s, %d exclude routes, %d exclude domains",
		JoinPrefixes(network.Routes), strings.Join(network.DNSServers, " "), len(network.ExcludeRoutes), network.Domains.Count())
}

// JoinPrefixes lists prefixes separated by spaces.
func JoinPrefixes(prefixes []*net.IPNet) string {
	var joined []string
	for _, prefix := range prefixes {
		joined = append(joined, prefix.String())
	}
	return strings.Join(joined, " ")
}

// gatewayAddresses lists every public address of the gateway, so none of them is routed into the tunnel.
func gatewayAddresses(ctx context.Context, resolver *net.Resolver, host, configured string) ([]net.IP, error) {
	addresses, err := resolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, fmt.Errorf("resolve gateway %s: %w", host, err)
	}
	if ip := net.ParseIP(configured); ip != nil {
		addresses = append(addresses, ip)
	}
	var unique []net.IP
	seen := map[string]bool{}
	for _, address := range addresses {
		if address.To4() == nil || seen[address.String()] {
			continue
		}
		seen[address.String()] = true
		unique = append(unique, address)
	}
	return unique, nil
}

func parseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	var parsed []*net.IPNet
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", cidr, err)
		}
		parsed = append(parsed, network)
	}
	return parsed, nil
}

// parseIncludeRoutes reads IPv4 addresses and CIDR ranges.
func parseIncludeRoutes(entries []string) ([]*net.IPNet, error) {
	var parsed []*net.IPNet
	for _, entry := range entries {
		cidr := strings.TrimSpace(entry)
		if !strings.Contains(cidr, "/") {
			cidr += "/32"
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil || network.IP.To4() == nil {
			return nil, fmt.Errorf("include route %q: want an IPv4 address or CIDR range", entry)
		}
		parsed = append(parsed, network)
	}
	return parsed, nil
}
