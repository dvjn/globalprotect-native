package exclude

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Mark is the firewall mark of excluded traffic. An ip rule sends it to the main table.
const Mark = 0x4501

const tableName = "gpn"

// minimumTimeout keeps an address in the set for at least this long, whatever its DNS TTL.
// Open connections stay excluded beyond it through their conntrack mark.
const minimumTimeout = 5 * time.Minute

// Firewall is the nftables table that marks and masquerades excluded traffic.
type Firewall struct {
	device string
}

// InstallFirewall creates the table. Traffic to an address in its set gets a conntrack mark;
// every packet of a marked connection gets the firewall mark, which reroutes it outside the
// tunnel, and leaves through another device with its source rewritten.
func InstallFirewall(device string) (*Firewall, error) {
	script := fmt.Sprintf(`table ip %[1]s {
	set excluded {
		type ipv4_addr
		flags timeout
	}
	chain output {
		type route hook output priority mangle; policy accept;
		ip daddr @excluded ct mark set %#[2]x
		ct mark %#[2]x meta mark set %#[2]x
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		meta mark %#[2]x oifname != %[3]q masquerade
	}
}
`, tableName, Mark, device)
	if err := runNft(script); err != nil {
		return nil, err
	}
	return &Firewall{device: device}, nil
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
	return runNft(fmt.Sprintf("add element ip %s excluded { %s }\n", tableName, strings.Join(elements, ", ")))
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
