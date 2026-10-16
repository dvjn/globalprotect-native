package hip

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Product is one detected security product in a HIP category.
// State is "yes", "no" or "n/a": real-time protection for anti-malware, enabled otherwise.
type Product struct {
	Category string
	Vendor   string
	Name     string
	Version  string
	State    string
}

// knownProduct is a product the official client's OPSWAT scan reports on Fedora,
// with the vendor and name strings it uses.
type knownProduct struct {
	category string
	vendor   string
	name     string
	packages []string
	// unit, when set, decides the state: "yes" while it is active, "no" otherwise.
	unit string
	// state is reported when no unit is set.
	state string
	// rootVersion reads the running version when gpn runs as root.
	rootVersion func() string
}

var catalog = []knownProduct{
	{category: "anti-malware", vendor: "CrowdStrike, Inc.", name: "Crowdstrike Falcon",
		packages: []string{"falcon-sensor"}, unit: "falcon-sensor.service", rootVersion: falconSensorVersion},
	{category: "disk-encryption", vendor: "GitLab Inc.", name: "cryptsetup",
		packages: []string{"cryptsetup"}, state: "n/a"},
	{category: "firewall", vendor: "IPTables", name: "IPTables",
		packages: []string{"iptables-nft", "iptables-legacy"}, unit: "iptables.service"},
	{category: "firewall", vendor: "The Netfilter Project", name: "nftables",
		packages: []string{"nftables"}, unit: "nftables.service"},
	{category: "firewall", vendor: "Red Hat, Inc.", name: "Firewalld",
		packages: []string{"firewalld"}, unit: "firewalld.service"},
	{category: "patch-management", vendor: "Red Hat, Inc.", name: "Dandified Yum",
		packages: []string{"dnf5", "dnf"}, state: "yes"},
	{category: "patch-management", vendor: "GNU", name: "RPM Package Manager",
		packages: []string{"rpm"}, state: "n/a"},
	{category: "patch-management", vendor: "GNU", name: "Flatpak",
		packages: []string{"flatpak"}, state: "n/a"},
}

// DetectProducts returns the catalog products installed on this machine.
func DetectProducts() []Product {
	var detected []Product
	for _, known := range catalog {
		version, installed := installedVersion(known.packages)
		if !installed {
			continue
		}
		if known.rootVersion != nil && os.Geteuid() == 0 {
			if running := known.rootVersion(); running != "" {
				version = running
			}
		}

		state := known.state
		if known.unit != "" {
			state = yesNo(exec.Command("systemctl", "is-active", "--quiet", known.unit).Run() == nil)
		}
		detected = append(detected, Product{
			Category: known.category,
			Vendor:   known.vendor,
			Name:     known.name,
			Version:  version,
			State:    state,
		})
	}
	return detected
}

func installedVersion(packages []string) (string, bool) {
	for _, name := range packages {
		output, err := exec.Command("rpm", "-q", "--queryformat", "%{VERSION}", name).Output()
		if err == nil {
			return strings.TrimSpace(string(output)), true
		}
	}
	return "", false
}

var falconVersionLine = regexp.MustCompile(`version = (\S+)`)

// falconSensorVersion asks the running sensor for its version. The RPM version lags behind,
// because the sensor updates itself.
func falconSensorVersion() string {
	output, err := exec.Command("/opt/CrowdStrike/falconctl", "-g", "--version").Output()
	if err != nil {
		return ""
	}
	if match := falconVersionLine.FindSubmatch(output); match != nil {
		return string(match[1])
	}
	return ""
}
