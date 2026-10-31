package hip

// Product is one detected security product in a HIP category.
// State is "yes", "no" or "n/a": real-time protection for anti-malware, enabled otherwise.
type Product struct {
	Category string
	Vendor   string
	Name     string
	Version  string
	State    string
}

// Drive is the encryption state of the file system holding one path.
type Drive struct {
	Name      string
	Encrypted bool
}

// Interface is a network interface with its addresses.
type Interface struct {
	Name string
	MAC  string
	IPv4 []string
	IPv6 []string
}

// Facts is what the platform observes about the machine's disks and network.
type Facts struct {
	Drives     []Drive
	Interfaces []Interface
}
