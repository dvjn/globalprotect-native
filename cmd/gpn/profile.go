package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/device"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/profile"
	"github.com/dvjn/globalprotect-native/internal/state"
)

// profileFlags adds the flags that locate the daemon's files, and returns how to load them.
func profileFlags(flags *flag.FlagSet) func() (profile.Profile, error) {
	configPath := flags.String("config", config.DefaultPath, "settings file")
	statePath := flags.String("state", state.DefaultPath, "state file with the portal cookie")
	clientVersion := flags.String("client-version", device.ClientVersion(), "GlobalProtect version reported to the portal")
	return func() (profile.Profile, error) {
		settings, err := config.Load(*configPath)
		if err != nil {
			return profile.Profile{}, err
		}
		return profile.Profile{Settings: settings, StatePath: *statePath, Identify: identify(*clientVersion)}, nil
	}
}

// identify describes the machine as the official Linux client does, with the device's own
// identity when the settings ask for it.
func identify(clientVersion string) func(config.Config, string) (gp.Identity, error) {
	return func(settings config.Config, hostID string) (gp.Identity, error) {
		serialNumber := ""
		if settings.DeviceIdentity {
			var err error
			if hostID, err = device.ProductUUID(); err != nil {
				return gp.Identity{}, fmt.Errorf("read the device identity (set device_identity: false to skip): %w", err)
			}
			if serialNumber, err = device.HardwareSerial(); err != nil {
				return gp.Identity{}, fmt.Errorf("read the device identity (set device_identity: false to skip): %w", err)
			}
		}
		computer, err := os.Hostname()
		if err != nil {
			return gp.Identity{}, err
		}
		return gp.Identity{
			HostID:        hostID,
			SerialNumber:  serialNumber,
			Computer:      computer,
			OSVersion:     osName(),
			ClientVersion: clientVersion,
		}, nil
	}
}

// osName describes the OS the way the official Linux client does, such as "Linux Fedora 44".
func osName() string {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "Linux"
	}
	defer file.Close()

	release := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if key, value, found := strings.Cut(scanner.Text(), "="); found {
			release[key] = strings.Trim(value, `"`)
		}
	}
	distribution := strings.TrimSuffix(release["NAME"], " Linux")
	return strings.TrimSpace("Linux " + distribution + " " + release["VERSION_ID"])
}
