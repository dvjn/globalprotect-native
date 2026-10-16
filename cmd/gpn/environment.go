package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/device"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/state"
)

// environment is what every root-side operation starts from: the daemon's settings and state.
type environment struct {
	settings      config.Config
	statePath     string
	clientVersion string
}

// environmentFlags adds the flags that locate the daemon's files, and returns how to load them.
func environmentFlags(flags *flag.FlagSet) func() (environment, error) {
	configPath := flags.String("config", config.DefaultPath, "settings file")
	statePath := flags.String("state", state.DefaultPath, "state file with the portal cookie")
	clientVersion := flags.String("client-version", device.ClientVersion(), "GlobalProtect version reported to the portal")
	return func() (environment, error) {
		settings, err := config.Load(*configPath)
		if err != nil {
			return environment{}, err
		}
		return environment{settings: settings, statePath: *statePath, clientVersion: *clientVersion}, nil
	}
}

// target is the portal and gateway to use: the settings file's, or else the user's saved choice.
// An empty gateway means the fastest one. Without a portal, nothing can start, but the daemon
// still runs, so a fresh install works and `gpn connect` can say what is missing.
func (env environment) target(saved *state.State) (portal, gateway string, err error) {
	portal, gateway = env.settings.Portal, env.settings.Gateway
	if portal == "" {
		portal = saved.Portal
	}
	if gateway == "" {
		gateway = saved.Gateway
	}
	if portal == "" {
		return "", "", fmt.Errorf("%w: run `gpn connect --portal HOST` once", errNotConfigured)
	}
	return portal, gateway, nil
}

// portalKnown reports whether the settings or a user's saved choice name a portal.
func (env environment) portalKnown() bool {
	saved, err := state.Load(env.statePath)
	if err != nil {
		return false
	}
	_, _, err = env.target(saved)
	return err == nil
}

// saveChoice records the portal and gateway a user picked; empty values keep the old choice.
func (env environment) saveChoice(portal, gateway string) error {
	if portal == "" && gateway == "" {
		return nil
	}
	saved, err := state.Load(env.statePath)
	if err != nil {
		return err
	}
	if portal != "" && portal != saved.Portal {
		saved.Portal = portal
		saved.Gateway = ""
	}
	if gateway != "" {
		saved.Gateway = gateway
	}
	return saved.Save(env.statePath)
}

// errNotConfigured means no portal is known yet; retrying cannot help.
var errNotConfigured = errors.New("not configured")

// load reads the state file and the machine identity.
func (env environment) load() (*state.State, gp.Identity, error) {
	saved, err := state.Load(env.statePath)
	if err != nil {
		return nil, gp.Identity{}, err
	}

	hostID, serialNumber := saved.HostID, ""
	if env.settings.DeviceIdentity {
		if hostID, err = device.ProductUUID(); err != nil {
			return nil, gp.Identity{}, fmt.Errorf("read the device identity (set device_identity: false to skip): %w", err)
		}
		if serialNumber, err = device.HardwareSerial(); err != nil {
			return nil, gp.Identity{}, fmt.Errorf("read the device identity (set device_identity: false to skip): %w", err)
		}
	}
	computer, err := os.Hostname()
	if err != nil {
		return nil, gp.Identity{}, err
	}
	return saved, gp.Identity{
		HostID:        hostID,
		SerialNumber:  serialNumber,
		Computer:      computer,
		OSVersion:     osName(),
		ClientVersion: env.clientVersion,
	}, nil
}

// portalClient is a client for the configured portal, with the machine identity.
func (env environment) portalClient() (*gp.Client, *state.State, error) {
	saved, identity, err := env.load()
	if err != nil {
		return nil, nil, err
	}
	portal, _, err := env.target(saved)
	if err != nil {
		return nil, nil, err
	}
	return gp.NewClient(portal, identity), saved, nil
}

func cookieCredential(cookie state.PortalCookie) gp.Credential {
	return gp.Credential{
		Username:               cookie.Username,
		UserAuthCookie:         cookie.UserAuthCookie,
		PrelogonUserAuthCookie: cookie.PrelogonUserAuthCookie,
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
