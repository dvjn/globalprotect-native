package desktop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dvjn/globalprotect-native/internal/control"
	"github.com/dvjn/globalprotect-native/internal/relay"
)

// agentRetryDelay is how long the agent waits before reaching the daemon again.
const agentRetryDelay = 5 * time.Second

// RunAgent follows the daemon for the desktop session until ctx ends: it shows a tray icon and
// notifications, and opens the browser when the daemon needs a new login. It runs as the user.
func RunAgent(ctx context.Context) {
	statusIcon := startTray(ctx)
	defer statusIcon.end()

	var last control.Status
	for ctx.Err() == nil {
		err := followDaemon(ctx, &last, statusIcon)
		if ctx.Err() != nil {
			return
		}
		statusIcon.showUnavailable()
		fmt.Fprintln(os.Stderr, "Lost the daemon, retrying:", err)
		select {
		case <-ctx.Done():
		case <-time.After(agentRetryDelay):
		}
	}
}

func followDaemon(ctx context.Context, last *control.Status, statusIcon *tray) error {
	watch, err := control.Dial()
	if err != nil {
		return err
	}
	defer watch.Close()
	go func() {
		<-ctx.Done()
		watch.Close()
	}()
	if err := watch.Send(control.Request{Command: control.CommandWatch}); err != nil {
		return err
	}

	for {
		response, err := watch.Receive()
		if err != nil {
			return err
		}
		status := *response.Status
		statusIcon.show(status)
		if status.Update.Available != last.Update.Available && status.Update.Available != "" && !status.Update.Installing {
			go offerUpdate(status.Update.Available)
		}
		if status.Update.Error != last.Update.Error && status.Update.Error != "" {
			notify("GlobalProtect update failed", status.Update.Error)
		}
		last.Update = status.Update
		if status.State == last.State && status.Gateway == last.Gateway {
			continue
		}
		announce(*last, status)
		*last = status

		if status.State == control.StateNeedsLogin {
			if err := BrowserLogin(ctx, ""); err != nil && !errors.Is(err, relay.ErrLoginPending) {
				notify("GlobalProtect login failed", err.Error())
			}
		}
	}
}

// announce shows a desktop notification for changes the user cares about.
func announce(previous, current control.Status) {
	switch current.State {
	case control.StateConnected:
		notify("GlobalProtect connected", fmt.Sprintf("%s over %s", current.Gateway, current.Transport))
	case control.StateNeedsLogin:
		notify("GlobalProtect needs a login", "Opening the browser.")
	case control.StateFailed:
		notify("GlobalProtect failed", current.Error)
	case control.StateDisconnected:
		if previous.State == control.StateConnected {
			notify("GlobalProtect disconnected", "")
		}
	}
}

// offerUpdate shows a notification about a newer release with a button that installs it.
// notify-send without --action, before libnotify 0.7.10, gets a plain notification instead.
func offerUpdate(version string) {
	summary, body := "GlobalProtect update available", fmt.Sprintf("Version %s is out.", version)
	fmt.Fprintln(os.Stderr, summary+":", body)
	output, err := exec.Command("notify-send", "--app-name=gpn", "--action=update=Update", "--wait", summary, body).Output()
	if err != nil {
		notify(summary, body+" Update from the tray menu or with `gpn update`.")
		return
	}
	if strings.TrimSpace(string(output)) == "update" {
		requestUpdate()
	}
}

// requestUpdate asks the daemon to install the latest release and shows its answer.
func requestUpdate() {
	response, err := control.Call(control.Request{Command: control.CommandUpdate})
	if err != nil {
		notify("GlobalProtect update failed", err.Error())
		return
	}
	notify("GlobalProtect update", response.Update)
}

func notify(summary, body string) {
	fmt.Fprintln(os.Stderr, summary+":", body)
	exec.Command("notify-send", "--app-name=gpn", summary, body).Run()
}
