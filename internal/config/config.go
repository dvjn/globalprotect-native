// Package config reads the daemon's settings from /etc/globalprotect-native/config.yaml.
// gpn detects everything it reports about the machine; the file only chooses the portal and
// gateway and switches features on or off.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"go.yaml.in/yaml/v3"
)

// DefaultPath is where the daemon reads its settings.
const DefaultPath = "/etc/globalprotect-native/config.yaml"

// Config holds the daemon's settings.
type Config struct {
	Portal  string `yaml:"portal"`
	Gateway string `yaml:"gateway"`
	// AutoConnect connects when the daemon starts, once a portal is known.
	AutoConnect bool `yaml:"auto_connect"`
	// DeviceIdentity sends the machine's SMBIOS UUID and serial number, as the official client
	// does. Without it gpn uses a host ID of its own, which Prisma treats as an unknown device.
	DeviceIdentity bool `yaml:"device_identity"`
	// SSLOnly skips ESP and always uses the SSL tunnel.
	SSLOnly bool `yaml:"ssl_only"`
	// ExcludeDomains are sent around the tunnel in addition to the gateway's own exclude list.
	// "*.example.com" matches the subdomains of example.com; other entries match exactly.
	ExcludeDomains []string `yaml:"exclude_domains,omitempty"`
	// IncludeDomains and IncludeRoutes, when either is set, are all that goes through the
	// tunnel, replacing the gateway's split tunneling and ExcludeDomains. Routes are IPv4
	// addresses or CIDR ranges.
	IncludeDomains []string `yaml:"include_domains,omitempty"`
	IncludeRoutes  []string `yaml:"include_routes,omitempty"`
	HIP            HIP      `yaml:"hip"`
}

// IncludeOnly reports whether only the included domains and routes go through the tunnel.
func (config Config) IncludeOnly() bool {
	return len(config.IncludeDomains) > 0 || len(config.IncludeRoutes) > 0
}

// HIP switches the host information profile report.
type HIP struct {
	Send bool `yaml:"send"`
}

// Default is the configuration used when the file does not exist.
func Default() Config {
	return Config{AutoConnect: true, DeviceIdentity: true, HIP: HIP{Send: true}}
}

// Load reads the file at path, falling back to Default for anything it leaves out.
func Load(path string) (Config, error) {
	config := Default()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return config, nil
	}
	if err != nil {
		return Config{}, err
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return config, nil
}
