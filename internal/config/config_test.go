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
	if config.Portal != "vpn.example.com" || !config.AutoConnect || !config.DeviceIdentity || !config.HIP.Send {
		t.Errorf("got %+v", config)
	}
}

func TestLoadSwitchesOff(t *testing.T) {
	config := loadText(t, "auto_connect: false\ndevice_identity: false\nhip:\n  send: false\n")
	if config.AutoConnect || config.DeviceIdentity || config.HIP.Send {
		t.Errorf("got %+v, want every switch off", config)
	}
}

func TestLoadExcludeDomains(t *testing.T) {
	config := loadText(t, "exclude_domains:\n  - \"*.youtube.com\"\n  - example.org\n")
	if !reflect.DeepEqual(config.ExcludeDomains, []string{"*.youtube.com", "example.org"}) {
		t.Errorf("got %q", config.ExcludeDomains)
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
