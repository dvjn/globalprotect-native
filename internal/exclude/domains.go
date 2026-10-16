// Package exclude sends traffic for the gateway's exclude domains around the tunnel.
package exclude

import (
	"strings"
)

// Domains matches names against the gateway's exclude-split-tunneling-domain list.
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

// Empty reports whether there is nothing to exclude.
func (domains Domains) Empty() bool {
	return domains.Count() == 0
}

// Match reports whether name, with or without a trailing dot, is excluded.
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
