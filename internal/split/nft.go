package split

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Mark is the firewall mark of split traffic. An ip rule sends it to the main table when it
// goes around the tunnel, or to the tunnel's table when it goes through it.
const Mark = 0x4501

const tableName = "gpn"

// minimumTimeout keeps an address in the set for at least this long, whatever its DNS TTL.
// Open connections stay split beyond it through their conntrack mark.
const minimumTimeout = 5 * time.Minute

// Direction is where marked traffic goes.
type Direction int

const (
	// Around sends marked traffic outside the tunnel.
	Around Direction = iota
	// Through sends marked traffic into the tunnel.
	Through
)

// Firewall is the nftables table that marks and masquerades split traffic.
type Firewall struct {
	device    string
	direction Direction
}

// InstallFirewall creates the table. Traffic to an address in its set gets a conntrack mark;
// every packet of a marked connection gets the firewall mark, which reroutes it, and leaves
// with its source rewritten when the route the socket first chose went through another device.
// Around, that is every marked packet not leaving through the tunnel device; through, every
// marked packet leaving through it.
func InstallFirewall(device string, direction Direction) (*Firewall, error) {
	outgoing := "!="
	if direction == Through {
		outgoing = "=="
	}
	script := fmt.Sprintf(`table ip %[1]s {
	set split {
		type ipv4_addr
		flags timeout
	}
	chain output {
		type route hook output priority mangle; policy accept;
		ip daddr @split ct mark set %#[2]x
		ct mark %#[2]x meta mark set %#[2]x
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		meta mark %#[2]x oifname %[4]s %[3]q masquerade
	}
}
`, tableName, Mark, device, outgoing)
	if err := runNft(script); err != nil {
		return nil, err
	}
	return &Firewall{device: device, direction: direction}, nil
}

// Add puts addresses into the set for ttl, or for minimumTimeout if that is longer.
func (firewall *Firewall) Add(addresses []net.IP, ttl time.Duration) error {
	if len(addresses) == 0 {
		return nil
	}
	timeout := max(ttl, minimumTimeout)
	var elements []string
	for _, address := range addresses {
		elements = append(elements, fmt.Sprintf("%s timeout %ds", address, int(timeout.Seconds())))
	}
	return runNft(fmt.Sprintf("add element ip %s split { %s }\n", tableName, strings.Join(elements, ", ")))
}

// Remove deletes the table.
func (firewall *Firewall) Remove() error {
	return RemoveLeftovers()
}

// RemoveLeftovers deletes the table if an earlier run left it.
func RemoveLeftovers() error {
	if exec.Command("nft", "list", "table", "ip", tableName).Run() != nil {
		return nil
	}
	return runNft(fmt.Sprintf("delete table ip %s\n", tableName))
}

func runNft(script string) error {
	command := exec.Command("nft", "-f", "-")
	command.Stdin = strings.NewReader(script)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, output)
	}
	return nil
}
