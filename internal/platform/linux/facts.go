package linux

import (
	"net"
	"os/exec"
	"strings"

	"github.com/dvjn/globalprotect-native/internal/hip"
)

// collectFacts inspects the machine. drivePaths are the paths whose file systems the report covers.
func collectFacts(drivePaths []string) hip.Facts {
	var facts hip.Facts
	for _, path := range drivePaths {
		facts.Drives = append(facts.Drives, hip.Drive{Name: path, Encrypted: isEncrypted(path)})
	}
	facts.Interfaces = hardwareInterfaces()
	return facts
}

// isEncrypted reports whether the file system holding path sits on a dm-crypt device.
func isEncrypted(path string) bool {
	source, err := exec.Command("findmnt", "--noheadings", "--nofsroot", "--output", "SOURCE", "--target", path).Output()
	if err != nil {
		return false
	}
	types, err := exec.Command("lsblk", "--inverse", "--noheadings", "--output", "TYPE", strings.TrimSpace(string(source))).Output()
	if err != nil {
		return false
	}
	for _, deviceType := range strings.Fields(string(types)) {
		if deviceType == "crypt" {
			return true
		}
	}
	return false
}

// hardwareInterfaces lists the interfaces that have a MAC address, as the official client
// does. Loopback and tunnel devices have none.
func hardwareInterfaces() []hip.Interface {
	links, err := net.Interfaces()
	if err != nil {
		return nil
	}

	var interfaces []hip.Interface
	for _, link := range links {
		if len(link.HardwareAddr) == 0 {
			continue
		}
		found := hip.Interface{Name: link.Name, MAC: link.HardwareAddr.String()}
		addresses, _ := link.Addrs()
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			switch {
			case err != nil:
			case ip.To4() != nil:
				found.IPv4 = append(found.IPv4, ip.String())
			default:
				found.IPv6 = append(found.IPv6, ip.String())
			}
		}
		interfaces = append(interfaces, found)
	}
	return interfaces
}
