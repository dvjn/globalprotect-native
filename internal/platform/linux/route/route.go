// Package route sends traffic through the tunnel with policy routing, leaving the main
// routing table to NetworkManager.
package route

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/dvjn/globalprotect-native/internal/platform/linux/link"
)

// Table is the routing table that holds the tunnel's routes.
const Table = 4501

// The rules sit just below the main table's rule at 32766.
const (
	priorityToMain     = 32700
	priorityMarked     = 32705
	prioritySuppressed = 32710
	priorityTunnel     = 32720
)

// Plan describes how traffic should flow while the tunnel is up.
type Plan struct {
	Device string
	// Gateways are the gateway's public addresses. Traffic to them stays outside the tunnel,
	// or the tunnel would carry itself.
	Gateways      []net.IP
	IncludeRoutes []*net.IPNet
	ExcludeRoutes []*net.IPNet
	// LocalNetworkAccess keeps the main table's specific routes, such as the LAN, docker
	// bridges and Tailscale, ahead of the tunnel.
	LocalNetworkAccess bool
	// ExcludeMark, when not zero, sends packets carrying this firewall mark to the main table.
	ExcludeMark int
	// IncludeOnly turns the plan around: only traffic to OnlyRoutes and packets carrying
	// OnlyMark go through the tunnel, and the rest stays in the main table. LocalNetworkAccess
	// and ExcludeMark do not apply.
	IncludeOnly bool
	OnlyRoutes  []*net.IPNet
	OnlyMark    int
}

// Routing is the installed state, kept so Remove can undo exactly what Apply did.
type Routing struct {
	rules  []*netlink.Rule
	routes []*netlink.Route
}

// Apply installs the plan.
func Apply(plan Plan) (*Routing, error) {
	routing := &Routing{}
	if err := routing.install(plan); err != nil {
		return nil, errors.Join(err, routing.Remove())
	}
	return routing, nil
}

func (routing *Routing) install(plan Plan) error {
	device, err := netlink.LinkByName(plan.Device)
	if err != nil {
		return err
	}
	if err := disableIPv6(plan.Device); err != nil {
		return err
	}

	for _, destination := range plan.IncludeRoutes {
		route := &netlink.Route{LinkIndex: device.Attrs().Index, Dst: destination, Scope: netlink.SCOPE_LINK, Table: Table}
		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("add route %s to table %d: %w", destination, Table, err)
		}
		routing.routes = append(routing.routes, route)
	}

	for _, gateway := range plan.Gateways {
		if err := routing.addRule(toMain(link.HostPrefix(gateway))); err != nil {
			return err
		}
	}
	for _, destination := range plan.ExcludeRoutes {
		if err := routing.addRule(toMain(destination)); err != nil {
			return err
		}
	}
	if plan.IncludeOnly {
		return routing.installIncludeOnly(plan)
	}
	if plan.ExcludeMark != 0 {
		if err := routing.addRule(marked(plan.ExcludeMark, unix.RT_TABLE_MAIN)); err != nil {
			return err
		}
	}
	if plan.LocalNetworkAccess {
		suppressed := netlink.NewRule()
		suppressed.Table = unix.RT_TABLE_MAIN
		suppressed.SuppressPrefixlen = 0
		suppressed.Priority = prioritySuppressed
		if err := routing.addRule(suppressed); err != nil {
			return err
		}
	}
	tunnel := netlink.NewRule()
	tunnel.Table = Table
	tunnel.Priority = priorityTunnel
	if err := routing.addRule(tunnel); err != nil {
		return err
	}
	return nil
}

// installIncludeOnly adds the rules that send only the chosen traffic to the tunnel's table.
// Without a catch-all rule, everything else falls through to the main table.
func (routing *Routing) installIncludeOnly(plan Plan) error {
	if plan.OnlyMark != 0 {
		if err := routing.addRule(marked(plan.OnlyMark, Table)); err != nil {
			return err
		}
	}
	for _, destination := range plan.OnlyRoutes {
		rule := netlink.NewRule()
		rule.Dst = destination
		rule.Table = Table
		rule.Priority = priorityTunnel
		if err := routing.addRule(rule); err != nil {
			return err
		}
	}
	return nil
}

func marked(mark, table int) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Mark = uint32(mark)
	rule.Table = table
	rule.Priority = priorityMarked
	return rule
}

func toMain(destination *net.IPNet) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Dst = destination
	rule.Table = unix.RT_TABLE_MAIN
	rule.Priority = priorityToMain
	return rule
}

func (routing *Routing) addRule(rule *netlink.Rule) error {
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("add rule to table %d: %w", rule.Table, err)
	}
	routing.rules = append(routing.rules, rule)
	return nil
}

// Remove deletes the rules and routes Apply installed.
func (routing *Routing) Remove() error {
	var errs []error
	for _, rule := range routing.rules {
		if err := netlink.RuleDel(rule); err != nil {
			errs = append(errs, err)
		}
	}
	for _, route := range routing.routes {
		if err := netlink.RouteDel(route); err != nil && !errors.Is(err, unix.ESRCH) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RemoveLeftovers deletes gpn rules a crashed run left behind.
func RemoveLeftovers() error {
	rules, err := netlink.RuleList(unix.AF_INET)
	if err != nil {
		return err
	}
	var errs []error
	for _, rule := range rules {
		if rule.Priority >= priorityToMain && rule.Priority <= priorityTunnel {
			errs = append(errs, netlink.RuleDel(&rule))
		}
	}
	return errors.Join(errs...)
}

// disableIPv6 stops the kernel from giving the device an IPv6 link-local address.
// The gateway sends no IPv6 configuration.
func disableIPv6(device string) error {
	path := filepath.Join("/proc/sys/net/ipv6/conf", device, "disable_ipv6")
	if err := os.WriteFile(path, []byte("1"), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("disable IPv6 on %s: %w", device, err)
	}
	return nil
}
