package hip

// Product is one detected security product in a HIP category.
// State is "yes", "no" or "n/a": real-time protection for anti-malware, enabled otherwise.
type Product struct {
	Category string `json:"category"`
	Vendor   string `json:"vendor"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	State    string `json:"state"`
}

// Drive is the encryption state of the file system holding one path.
type Drive struct {
	Name      string `json:"name"`
	Encrypted bool   `json:"encrypted"`
}

// Interface is a network interface with its addresses.
type Interface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPv4 []string `json:"ipv4,omitempty"`
	IPv6 []string `json:"ipv6,omitempty"`
}

// Facts is what the platform observes about the machine's disks and network.
type Facts struct {
	Drives     []Drive
	Interfaces []Interface
}
