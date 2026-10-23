// Package split picks out the traffic of chosen domains, by the addresses their DNS answers
// carry, and sends it around the tunnel or, in include-only mode, through it alone.
package split

import (
	"slices"
	"strings"
)

// Domains matches names against a split tunneling domain list, such as the gateway's
// exclude-split-tunneling-domain list.
// "*.example.com" matches every subdomain of example.com but not example.com itself;
// any other entry matches only itself. A trailing ":port" is ignored.
type Domains struct {
	exact    map[string]bool
	suffixes []string
}

// NewDomains builds a matcher from the gateway's entries.
func NewDomains(entries []string) Domains {
	domains := Domains{exact: map[string]bool{}}
	for _, entry := range entries {
		host, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(entry)), ":")
		if parent, wildcard := strings.CutPrefix(host, "*."); wildcard {
			domains.suffixes = append(domains.suffixes, "."+parent)
		} else if host != "" {
			domains.exact[host] = true
		}
	}
	return domains
}

// Count is the number of distinct entries.
func (domains Domains) Count() int {
	return len(domains.exact) + len(domains.suffixes)
}

// Empty reports whether there are no entries.
func (domains Domains) Empty() bool {
	return domains.Count() == 0
}

// Match reports whether name, with or without a trailing dot, matches an entry.
func (domains Domains) Match(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if domains.exact[name] {
		return true
	}
	for _, suffix := range domains.suffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// RoutingDomains are the systemd-resolved routing domains that send every matching name to a
// link's servers. "~example.com" also covers example.com itself, which "*.example.com" does not
// match; its answers go unrecorded.
func (domains Domains) RoutingDomains() []string {
	var routing []string
	for host := range domains.exact {
		routing = append(routing, "~"+host)
	}
	for _, suffix := range domains.suffixes {
		routing = append(routing, "~"+strings.TrimPrefix(suffix, "."))
	}
	slices.Sort(routing)
	return slices.Compact(routing)
}
