package main

import (
	"flag"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/platform/linux"
	"github.com/dvjn/globalprotect-native/internal/profile"
	"github.com/dvjn/globalprotect-native/internal/state"
)

// profileFlags adds the flags that locate the daemon's files, and returns how to load them.
func profileFlags(flags *flag.FlagSet) func() (profile.Profile, error) {
	configPath := flags.String("config", config.DefaultPath, "settings file")
	statePath := flags.String("state", state.DefaultPath, "state file with the portal cookie")
	clientVersion := flags.String("client-version", linux.ClientVersion(), "GlobalProtect version reported to the portal")
	return func() (profile.Profile, error) {
		settings, err := config.Load(*configPath)
		if err != nil {
			return profile.Profile{}, err
		}
		return profile.Profile{Settings: settings, StatePath: *statePath, Identify: linux.Identify(*clientVersion)}, nil
	}
}
