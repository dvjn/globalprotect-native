// Package desktop is gpn in the user's desktop session: the agent with its tray icon and
// notifications, the browser login, and the per-user setup.
package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	callbackDesktopFile = "gpn-callback.desktop"
	callbackMimeType    = "x-scheme-handler/globalprotectcallback"
	agentUnit           = "gpn-agent.service"
)

// SetUp finishes the per-user part of an install the first time the user runs gpn:
// gpn becomes the handler for login callbacks, and the agent is enabled as a user service that
// starts now and with each desktop login. Both steps are skipped when already done or when the
// package did not install their files.
func SetUp() {
	if handler, err := exec.Command("xdg-mime", "query", "default", callbackMimeType).Output(); err == nil &&
		strings.TrimSpace(string(handler)) != callbackDesktopFile && installed("/usr/share/applications/"+callbackDesktopFile) {
		if exec.Command("xdg-mime", "default", callbackDesktopFile, callbackMimeType).Run() == nil {
			fmt.Fprintln(os.Stderr, "gpn now handles GlobalProtect login links; it passes them to the official client when it is not logging in itself.")
		}
	}

	if !installed("/usr/lib/systemd/user/" + agentUnit) {
		return
	}
	switch {
	case exec.Command("systemctl", "--user", "is-enabled", "--quiet", agentUnit).Run() != nil:
		if exec.Command("systemctl", "--user", "enable", "--now", agentUnit).Run() == nil {
			fmt.Fprintln(os.Stderr, "Enabled the gpn agent: its tray icon connects, disconnects and logs in, and it starts with each desktop login.")
		}
	case exec.Command("systemctl", "--user", "is-active", "--quiet", agentUnit).Run() != nil:
		if exec.Command("systemctl", "--user", "start", agentUnit).Run() == nil {
			fmt.Fprintln(os.Stderr, "Started the gpn agent.")
		}
	case agentBinaryReplaced():
		if exec.Command("systemctl", "--user", "restart", agentUnit).Run() == nil {
			fmt.Fprintln(os.Stderr, "Restarted the gpn agent on the upgraded gpn.")
		}
	}
}

// agentBinaryReplaced reports whether the running agent's executable was deleted or replaced
// since it started, as a package upgrade does.
func agentBinaryReplaced() bool {
	pid, err := exec.Command("systemctl", "--user", "show", "--property=MainPID", "--value", agentUnit).Output()
	if err != nil {
		return false
	}
	executable, err := os.Readlink("/proc/" + strings.TrimSpace(string(pid)) + "/exe")
	return err == nil && strings.HasSuffix(executable, " (deleted)")
}

func installed(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
