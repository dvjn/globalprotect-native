package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/control"
	"github.com/dvjn/globalprotect-native/internal/dns"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/route"
	"github.com/dvjn/globalprotect-native/internal/split"
	"github.com/dvjn/globalprotect-native/internal/tun"
	"github.com/dvjn/globalprotect-native/internal/tunnel"
)

const (
	deviceName        = "gpn0"
	defaultMTU        = 1280
	keepaliveInterval = 10 * time.Second
	deadAfter         = 30 * time.Second
)

// tunnelOptions are what the caller of runTunnel provides besides the environment.
type tunnelOptions struct {
	// userHome is the home directory of the user who asked for the tunnel; the HIP report
	// states whether its file system is encrypted.
	userHome string
	// onConnected is called once the tunnel carries traffic.
	onConnected func(control.Status)
}

// runTunnel connects to the configured gateway and carries traffic until ctx ends, returning nil,
// or until the tunnel fails, returning why.
func runTunnel(ctx context.Context, env environment, options tunnelOptions) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := removeLeftovers(); err != nil {
		return fmt.Errorf("clean up after an earlier run: %w", err)
	}

	opened, err := openGatewaySession(ctx, env)
	if err != nil {
		return err
	}
	defer opened.logOut()

	gatewayConfig, _, err := opened.client.GatewayGetConfig(ctx, opened.session)
	if err != nil {
		return err
	}
	if gatewayConfig.Quarantined {
		fmt.Fprintln(os.Stderr, "Warning: the gateway reports this machine as quarantined.")
	}
	if env.settings.HIP.Send {
		if err := sendHIPReportIfNeeded(ctx, opened, gatewayConfig.ClientIP, options.userHome); err != nil {
			return err
		}
	}

	traffic, err := newTrafficPlan(opened.gateway.Address, gatewayConfig, env.settings)
	if err != nil {
		return err
	}
	mtu := gatewayConfig.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	watchdog, err := newWatchdog(net.ParseIP(gatewayConfig.GatewayAddress), rekeyInterval(gatewayConfig.IdleTimeout))
	if err != nil {
		return err
	}
	if env.settings.HIP.Send {
		interval := time.Duration(opened.portalConfig.HIPReportInterval) * time.Second
		go resendHIPReports(ctx, opened, gatewayConfig.ClientIP, options.userHome, interval)
	}
	connected := func(transport string) {
		fmt.Fprintf(os.Stderr, "Connected to %s over %s: %s %s, MTU %d, %s\n",
			opened.gateway.Name, transport, deviceName, gatewayConfig.ClientIP, mtu, traffic)
		options.onConnected(control.Status{
			State:     control.StateConnected,
			Gateway:   opened.gateway.Name,
			ClientIP:  gatewayConfig.ClientIP,
			Transport: transport,
		})
	}

	if !env.settings.SSLOnly && gatewayConfig.ESP != nil {
		err := runESP(ctx, gatewayConfig, mtu, traffic, watchdog, connected)
		if !errors.Is(err, errESPUnavailable) {
			return err
		}
		fmt.Fprintln(os.Stderr, "Falling back to the SSL tunnel:", err)
	}
	return runSSL(ctx, opened, gatewayConfig, mtu, traffic, watchdog, connected)
}

// A tunnel stops with one of these when it should be built again at once, without backoff.
var (
	errRekeyDue       = errors.New("rekey due")
	errNetworkChanged = errors.New("network changed")
)

func needsRebuild(err error) bool {
	return errors.Is(err, errRekeyDue) || errors.Is(err, errNetworkChanged)
}

// watchdog notices, on every keepalive, that the tunnel must be rebuilt: its keys are about
// to expire, or the local address that reaches the gateway changed, as after a Wi-Fi switch.
type watchdog struct {
	gateway net.IP
	outer   net.IP
	rekeyAt time.Time
}

func newWatchdog(gateway net.IP, rekeyAfter time.Duration) (watchdog, error) {
	outer, err := tunnel.OuterAddress(gateway)
	if err != nil {
		return watchdog{}, err
	}
	dog := watchdog{gateway: gateway, outer: outer}
	if rekeyAfter > 0 {
		dog.rekeyAt = time.Now().Add(rekeyAfter)
	}
	return dog, nil
}

func (dog watchdog) check() error {
	if !dog.rekeyAt.IsZero() && time.Now().After(dog.rekeyAt) {
		return errRekeyDue
	}
	current, err := tunnel.OuterAddress(dog.gateway)
	if err != nil {
		return fmt.Errorf("%w: %w", errNetworkChanged, err)
	}
	if !current.Equal(dog.outer) {
		return fmt.Errorf("%w: local address %s is now %s", errNetworkChanged, dog.outer, current)
	}
	return nil
}

// rekeyInterval is when to rebuild the tunnel: a minute before the gateway's <timeout>, which
// OpenConnect treats as the rekey interval.
func rekeyInterval(timeoutSeconds int) time.Duration {
	timeout := time.Duration(timeoutSeconds) * time.Second
	if timeout <= 2*time.Minute {
		return 0
	}
	return timeout - time.Minute
}

// resendHIPReports sends a report whenever the gateway wants one, every interval, until ctx ends.
func resendHIPReports(ctx context.Context, opened gatewaySession, clientIP, userHome string, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sendHIPReportIfNeeded(ctx, opened, clientIP, userHome); err != nil {
				fmt.Fprintln(os.Stderr, "HIP report:", err)
			}
		}
	}
}

// runCleanup removes what a killed daemon left behind, so the network works again without it.
func runCleanup(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: gpn cleanup")
	}
	if os.Geteuid() != 0 {
		return errors.New("cleanup changes network settings; run it as root")
	}
	lock, err := lockDaemon()
	if err != nil {
		return fmt.Errorf("%w; stop it instead, it cleans up after itself", err)
	}
	defer lock.Close()
	return removeLeftovers()
}

// removeLeftovers deletes rules, the tunnel device, XFRM state, the split table and a
// replaced resolv.conf that an earlier run did not get to remove. resolved forgets the
// device's DNS settings together with the device.
func removeLeftovers() error {
	return errors.Join(
		route.RemoveLeftovers(),
		dns.RestoreLeftovers(),
		split.RemoveLeftovers(),
		tunnel.RemoveLeftovers(deviceName, espInterfaceID),
	)
}

// trafficPlan is how traffic and DNS flow while the tunnel is up.
type trafficPlan struct {
	routing route.Plan
	dns     dns.Settings
	// domains leave outside the tunnel, or alone go through it in include-only mode; a DNS
	// forwarder on clientIP finds their addresses.
	domains   split.Domains
	direction split.Direction
	clientIP  net.IP
}

// newTrafficPlan resolves everything the plan needs before the tunnel takes over DNS.
func newTrafficPlan(gatewayHost string, gatewayConfig gp.GatewayConfig, settings config.Config) (trafficPlan, error) {
	gateways, err := gatewayAddresses(gatewayHost, gatewayConfig.GatewayAddress)
	if err != nil {
		return trafficPlan{}, err
	}
	include, err := parseCIDRs(gatewayConfig.IncludeRoutes)
	if err != nil {
		return trafficPlan{}, err
	}
	excludeRoutes, err := parseCIDRs(gatewayConfig.ExcludeRoutes)
	if err != nil {
		return trafficPlan{}, err
	}
	plan := trafficPlan{
		routing: route.Plan{
			Device:             deviceName,
			Gateways:           gateways,
			IncludeRoutes:      include,
			ExcludeRoutes:      excludeRoutes,
			LocalNetworkAccess: gatewayConfig.LocalNetworkAccess,
		},
		dns:      dns.Settings{Device: deviceName, Servers: gatewayConfig.DNSServers, Suffixes: gatewayConfig.DNSSuffixes},
		clientIP: net.ParseIP(gatewayConfig.ClientIP),
	}
	if settings.IncludeOnly() {
		return plan.includeOnly(settings)
	}
	plan.domains = split.NewDomains(append(gatewayConfig.ExcludeDomains, settings.ExcludeDomains...))
	plan.direction = split.Around
	if !plan.domains.Empty() {
		plan.routing.ExcludeMark = split.Mark
	}
	return plan, nil
}

// includeOnly limits the tunnel to the configured routes and domains, and to the tunnel's DNS
// servers, which answer for the domains and the gateway's DNS suffixes. Every other name is
// resolved, and every other address reached, outside the tunnel.
func (plan trafficPlan) includeOnly(settings config.Config) (trafficPlan, error) {
	only, err := parseIncludeRoutes(settings.IncludeRoutes)
	if err != nil {
		return trafficPlan{}, err
	}
	for _, server := range plan.dns.Servers {
		if address := net.ParseIP(server).To4(); address != nil {
			only = append(only, route.HostPrefix(address))
		}
	}
	plan.routing.IncludeOnly = true
	plan.routing.IncludeRoutes = []*net.IPNet{{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}}
	plan.routing.OnlyRoutes = only
	plan.domains = split.NewDomains(settings.IncludeDomains)
	plan.direction = split.Through
	plan.dns.Selective = true
	if !plan.domains.Empty() {
		plan.routing.OnlyMark = split.Mark
		plan.dns.RoutingDomains = plan.domains.RoutingDomains()
	}
	return plan, nil
}

// apply installs the routes, the split-domain forwarder and the DNS settings on the tunnel
// device, and returns how to undo them in reverse order.
func (plan trafficPlan) apply() (undo func(), err error) {
	var undoSteps []func() error
	undo = func() {
		var errs []error
		for i := len(undoSteps) - 1; i >= 0; i-- {
			errs = append(errs, undoSteps[i]())
		}
		if err := errors.Join(errs...); err != nil {
			fmt.Fprintln(os.Stderr, "Cleanup failed:", err)
		}
	}
	defer func() {
		if err != nil {
			undo()
		}
	}()

	routing, err := route.Apply(plan.routing)
	if err != nil {
		return nil, err
	}
	undoSteps = append(undoSteps, routing.Remove)

	dnsSettings := plan.dns
	if !plan.domains.Empty() {
		firewall, err := split.InstallFirewall(plan.routing.Device, plan.direction)
		if err != nil {
			return nil, err
		}
		undoSteps = append(undoSteps, firewall.Remove)

		forwarder, err := split.StartForwarder(plan.clientIP, plan.dns.Servers, plan.domains, firewall)
		if err != nil {
			return nil, err
		}
		undoSteps = append(undoSteps, forwarder.Close)
		dnsSettings.Servers = []string{plan.clientIP.String()}
	}

	restoreDNS, err := dns.Apply(dnsSettings)
	if err != nil {
		return nil, err
	}
	undoSteps = append(undoSteps, restoreDNS)
	return undo, nil
}

func (plan trafficPlan) String() string {
	if plan.routing.IncludeOnly {
		return fmt.Sprintf("include only: routes %s, %d include domains, DNS %s",
			joinPrefixes(plan.routing.OnlyRoutes), plan.domains.Count(), strings.Join(plan.dns.Servers, " "))
	}
	return fmt.Sprintf("routes %s, DNS %s, %d exclude routes, %d exclude domains",
		joinPrefixes(plan.routing.IncludeRoutes), strings.Join(plan.dns.Servers, " "), len(plan.routing.ExcludeRoutes), plan.domains.Count())
}

func joinPrefixes(prefixes []*net.IPNet) string {
	var joined []string
	for _, prefix := range prefixes {
		joined = append(joined, prefix.String())
	}
	return strings.Join(joined, " ")
}

// gatewayAddresses lists every public address of the gateway, so none of them is routed into the tunnel.
func gatewayAddresses(host, configured string) ([]net.IP, error) {
	addresses, err := net.LookupIP(host)
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

// espInterfaceID is the XFRM if_id that ties gpn's ESP policies to its interface.
const espInterfaceID = 0x4501

// errESPUnavailable means ESP could not be set up or the gateway did not answer over it.
var errESPUnavailable = errors.New("ESP unavailable")

// espProbeTime is how long gpn waits for the first magic ping reply before falling back to SSL.
const espProbeTime = 10 * time.Second

// runESP carries traffic over ESP until ctx ends or the gateway stops answering.
func runESP(ctx context.Context, gatewayConfig gp.GatewayConfig, mtu int, traffic trafficPlan, dog watchdog, connected func(string)) error {
	esp, err := tunnel.OpenESP(deviceName, espInterfaceID, net.ParseIP(gatewayConfig.ClientIP),
		net.ParseIP(gatewayConfig.GatewayAddress), mtu, *gatewayConfig.ESP)
	if err != nil {
		return fmt.Errorf("%w: %w", errESPUnavailable, err)
	}
	defer esp.Close()

	if err := waitForMagicReply(esp, espProbeTime); err != nil {
		return fmt.Errorf("%w: %w", errESPUnavailable, err)
	}
	undo, err := traffic.apply()
	if err != nil {
		return err
	}
	defer undo()

	connected("ESP")
	return keepESPAlive(ctx, esp, dog)
}

func waitForMagicReply(esp *tunnel.ESP, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for sequence := uint16(0); time.Now().Before(deadline); sequence++ {
		if err := esp.SendMagicPing(sequence); err != nil {
			return err
		}
		err := esp.ReadMagicReply()
		if err == nil {
			return nil
		}
		if !tunnel.IsTimeout(err) {
			return err
		}
	}
	return fmt.Errorf("no magic ping reply within %s", timeout)
}

// keepESPAlive pings the gateway every keepaliveInterval and gives up after deadAfter without a
// reply, or when the watchdog says the tunnel must be rebuilt.
func keepESPAlive(ctx context.Context, esp *tunnel.ESP, dog watchdog) error {
	var lastReply atomic.Int64
	lastReply.Store(time.Now().UnixNano())
	failures := make(chan error, 1)
	go func() {
		for ctx.Err() == nil {
			err := esp.ReadMagicReply()
			switch {
			case err == nil:
				lastReply.Store(time.Now().UnixNano())
			case !tunnel.IsTimeout(err):
				failures <- fmt.Errorf("read magic ping reply: %w", err)
				return
			}
		}
	}()

	keepalive := time.NewTicker(keepaliveInterval)
	defer keepalive.Stop()
	for sequence := uint16(1); ; sequence++ {
		select {
		case <-ctx.Done():
			return nil
		case err := <-failures:
			return err
		case <-keepalive.C:
			if quiet := time.Since(time.Unix(0, lastReply.Load())); quiet > deadAfter {
				return fmt.Errorf("ESP tunnel dead: no magic ping reply for %s", quiet.Round(time.Second))
			}
			if err := dog.check(); err != nil {
				return err
			}
			if err := esp.SendMagicPing(sequence); err != nil {
				return fmt.Errorf("send magic ping: %w", err)
			}
		}
	}
}

// runSSL carries traffic over the SSL tunnel through a TUN device.
func runSSL(ctx context.Context, opened gatewaySession, gatewayConfig gp.GatewayConfig, mtu int, traffic trafficPlan, dog watchdog, connected func(string)) error {
	tunDevice, err := tun.Create(deviceName)
	if err != nil {
		return err
	}
	defer tunDevice.Close()
	if err := tunDevice.Configure(net.ParseIP(gatewayConfig.ClientIP), mtu); err != nil {
		return err
	}

	sslTunnel, err := tunnel.DialSSL(ctx, opened.gateway.Address, gatewayConfig.SSLTunnelPath, opened.session.Username, opened.session.AuthCookie)
	if err != nil {
		return err
	}
	defer sslTunnel.Close()

	undo, err := traffic.apply()
	if err != nil {
		return err
	}
	defer undo()

	connected("SSL")
	return forwardPackets(ctx, tunDevice, sslTunnel, mtu, dog)
}

// forwardPackets copies packets both ways until ctx ends, the tunnel fails or goes quiet, or the
// watchdog says the tunnel must be rebuilt.
func forwardPackets(ctx context.Context, device *tun.Device, sslTunnel *tunnel.SSL, mtu int, dog watchdog) error {
	var lastReceived atomic.Int64
	lastReceived.Store(time.Now().UnixNano())
	failures := make(chan error, 2)

	go func() {
		packet := make([]byte, mtu)
		for {
			length, err := device.Read(packet)
			if err != nil {
				failures <- fmt.Errorf("read %s: %w", device.Name, err)
				return
			}
			if err := sslTunnel.WritePacket(packet[:length]); err != nil {
				failures <- fmt.Errorf("send to gateway: %w", err)
				return
			}
		}
	}()

	go func() {
		for {
			packet, err := sslTunnel.ReadPacket()
			if err != nil {
				failures <- fmt.Errorf("receive from gateway: %w", err)
				return
			}
			lastReceived.Store(time.Now().UnixNano())
			if packet == nil {
				continue
			}
			if _, err := device.Write(packet); err != nil {
				failures <- fmt.Errorf("write %s: %w", device.Name, err)
				return
			}
		}
	}()

	keepalive := time.NewTicker(keepaliveInterval)
	defer keepalive.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-failures:
			return err
		case <-keepalive.C:
			if quiet := time.Since(time.Unix(0, lastReceived.Load())); quiet > deadAfter {
				return fmt.Errorf("tunnel dead: nothing received for %s", quiet.Round(time.Second))
			}
			if err := dog.check(); err != nil {
				return err
			}
			if err := sslTunnel.SendKeepalive(); err != nil {
				return fmt.Errorf("send keepalive: %w", err)
			}
		}
	}
}
