package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/dvjn/globalprotect-native/internal/control"
	"github.com/dvjn/globalprotect-native/internal/relay"
)

// agentRetryDelay is how long the agent waits before reaching the daemon again.
const agentRetryDelay = 5 * time.Second

// runAgent follows the daemon for the desktop session: it shows notifications and opens the
// browser when the daemon needs a new login. It runs as the user.
func runAgent(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: gpn agent")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	statusIcon := startTray(ctx)
	defer statusIcon.end()

	var last control.Status
	for ctx.Err() == nil {
		err := followDaemon(ctx, &last, statusIcon)
		if ctx.Err() != nil {
			return nil
		}
		statusIcon.showUnavailable()
		fmt.Fprintln(os.Stderr, "Lost the daemon, retrying:", err)
		select {
		case <-ctx.Done():
		case <-time.After(agentRetryDelay):
		}
	}
	return nil
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
		if status.State == last.State && status.Gateway == last.Gateway {
			continue
		}
		announce(*last, status)
		*last = status

		if status.State == control.StateNeedsLogin {
			if err := browserLogin(ctx, ""); err != nil && !errors.Is(err, relay.ErrLoginPending) {
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

func notify(summary, body string) {
	fmt.Fprintln(os.Stderr, summary+":", body)
	exec.Command("notify-send", "--app-name=gpn", summary, body).Run()
}
