package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadMissingFileReturnsDefault(t *testing.T) {
	config, err := Load(filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(config, Default()) {
		t.Errorf("got %+v, want the default", config)
	}
}

func TestLoadKeepsDefaultsForMissingKeys(t *testing.T) {
	config := loadText(t, "portal: vpn.example.com\n")
	if config.Portal != "vpn.example.com" || !config.AutoConnect || !config.DeviceIdentity || !config.KernelESP || !config.CheckUpdates || !config.HIP.Send {
		t.Errorf("got %+v", config)
	}
}

func TestLoadSwitchesOff(t *testing.T) {
	config := loadText(t, "auto_connect: false\ndevice_identity: false\nkernel_esp: false\ncheck_updates: false\nhip:\n  send: false\n")
	if config.AutoConnect || config.DeviceIdentity || config.KernelESP || config.CheckUpdates || config.HIP.Send {
		t.Errorf("got %+v, want every switch off", config)
	}
}

func TestLoadExcludeDomains(t *testing.T) {
	config := loadText(t, "exclude_domains:\n  - \"*.youtube.com\"\n  - example.org\n")
	if !reflect.DeepEqual(config.ExcludeDomains, []string{"*.youtube.com", "example.org"}) {
		t.Errorf("got %q", config.ExcludeDomains)
	}
}

func TestLoadInclude(t *testing.T) {
	if Default().IncludeOnly() {
		t.Error("the default config is include-only")
	}
	config := loadText(t, "include_domains:\n  - \"*.corp.example\"\ninclude_routes:\n  - 10.0.0.0/8\n  - 192.0.2.7\n")
	if !reflect.DeepEqual(config.IncludeDomains, []string{"*.corp.example"}) ||
		!reflect.DeepEqual(config.IncludeRoutes, []string{"10.0.0.0/8", "192.0.2.7"}) || !config.IncludeOnly() {
		t.Errorf("got %q, %q", config.IncludeDomains, config.IncludeRoutes)
	}
	if !loadText(t, "include_routes: [10.0.0.0/8]\n").IncludeOnly() {
		t.Error("include routes alone are not include-only")
	}
}

func loadText(t *testing.T, text string) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return config
}
