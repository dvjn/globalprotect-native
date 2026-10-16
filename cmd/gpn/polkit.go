package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
)

// controlAction is the polkit action that guards the daemon. Its policy, shipped by the package,
// allows active local sessions and asks for admin authentication elsewhere.
const controlAction = "org.dvjn.globalprotect-native.control"

// polkitAllows asks polkit, without interaction, whether the process pid run by uid may control
// the VPN. polkit identifies a process by its pid and start time, so a reused pid cannot pass.
func polkitAllows(pid int32, uid uint32) (bool, error) {
	startTime, err := processStartTime(pid)
	if err != nil {
		return false, err
	}
	bus, err := dbus.ConnectSystemBus()
	if err != nil {
		return false, err
	}
	defer bus.Close()

	subject := struct {
		Kind    string
		Details map[string]dbus.Variant
	}{
		Kind: "unix-process",
		Details: map[string]dbus.Variant{
			"pid":        dbus.MakeVariant(uint32(pid)),
			"start-time": dbus.MakeVariant(startTime),
			"uid":        dbus.MakeVariant(int32(uid)),
		},
	}
	var result struct {
		Authorized bool
		Challenge  bool
		Details    map[string]string
	}
	authority := bus.Object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority")
	err = authority.Call("org.freedesktop.PolicyKit1.Authority.CheckAuthorization", 0,
		subject, controlAction, map[string]string{}, uint32(0), "").Store(&result)
	if err != nil {
		return false, fmt.Errorf("polkit: %w", err)
	}
	return result.Authorized, nil
}

// processStartTime is field 22 of /proc/<pid>/stat, in clock ticks since boot (proc(5)).
// The process name before it may contain spaces, so counting starts after its closing ")".
func processStartTime(pid int32) (uint64, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	afterName := string(stat[strings.LastIndexByte(string(stat), ')')+1:])
	fields := strings.Fields(afterName)
	// fields[0] is field 3 (state), so field 22 is fields[19].
	if len(fields) < 20 {
		return 0, fmt.Errorf("short /proc/%d/stat", pid)
	}
	return strconv.ParseUint(fields[19], 10, 64)
}
