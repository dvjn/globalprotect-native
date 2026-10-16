package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"github.com/dvjn/globalprotect-native/internal/control"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/loginpage"
	"github.com/dvjn/globalprotect-native/internal/relay"
)

func runStatus(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: gpn status")
	}
	response, err := control.Call(control.Request{Command: control.CommandStatus})
	if err != nil {
		return err
	}
	printStatus(*response.Status)
	return nil
}

func runDisconnect(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: gpn disconnect")
	}
	response, err := control.Call(control.Request{Command: control.CommandDisconnect})
	if err != nil {
		return err
	}
	printStatus(*response.Status)
	return nil
}

func runReconnect(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: gpn reconnect")
	}
	response, err := control.Call(control.Request{Command: control.CommandReconnect})
	if err != nil {
		return err
	}
	printStatus(*response.Status)
	return nil
}

func runLogin(args []string) error {
	flags := flag.NewFlagSet("login", flag.ExitOnError)
	portal := flags.String("portal", "", "portal host name, such as vpn.example.com; remembered by the daemon")
	flags.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return browserLogin(ctx, *portal)
}

// runConnect asks the daemon to connect and follows it until the tunnel is up or has failed,
// logging in through the browser when the daemon asks for it.
func runConnect(args []string) error {
	flags := flag.NewFlagSet("connect", flag.ExitOnError)
	portal := flags.String("portal", "", "portal host name, such as vpn.example.com; remembered by the daemon")
	gateway := flags.String("gateway", "", "gateway name; remembered by the daemon (default: the fastest)")
	flags.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	request := control.Request{Command: control.CommandConnect, Portal: *portal, Gateway: *gateway}
	if _, err := control.Call(request); err != nil {
		return err
	}
	watch, err := control.Dial()
	if err != nil {
		return err
	}
	defer watch.Close()
	if err := watch.Send(control.Request{Command: control.CommandWatch}); err != nil {
		return err
	}

	statuses := make(chan control.Status)
	failures := make(chan error, 1)
	go func() {
		for {
			response, err := watch.Receive()
			if err != nil {
				failures <- err
				return
			}
			statuses <- *response.Status
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-failures:
			return err
		case status := <-statuses:
			printStatus(status)
			switch status.State {
			case control.StateConnected:
				return nil
			case control.StateFailed:
				return errors.New(status.Error)
			case control.StateNeedsLogin:
				err := browserLogin(ctx, "")
				if errors.Is(err, relay.ErrLoginPending) {
					fmt.Fprintln(os.Stderr, "Waiting for the login already open in the browser.")
				} else if err != nil {
					return err
				}
			}
		}
	}
}

// browserLogin opens the portal's login page in the browser and hands the result to the daemon.
// An empty portal means the one the daemon already knows. It claims the callback socket before
// asking for a login page, so a second login fails with relay.ErrLoginPending without disturbing
// the first.
func browserLogin(ctx context.Context, portal string) error {
	socketPath, err := relay.SocketPath()
	if err != nil {
		return err
	}
	listener, err := relay.Listen(socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()

	response, err := control.Call(control.Request{Command: control.CommandPrelogin, Portal: portal})
	if err != nil {
		return err
	}
	callbackURI, err := waitForBrowserLogin(ctx, listener, response.LoginPage, response.LoginTimeout)
	if err != nil {
		return err
	}
	callback, err := gp.ParseCallback(callbackURI)
	if err != nil {
		return err
	}
	if _, err := control.Call(control.Request{Command: control.CommandLogin, Username: callback.Username, Token: callback.Token}); err != nil {
		return err
	}
	fmt.Println("Logged in as", callback.Username)
	return nil
}

// waitForBrowserLogin serves page on localhost, opens it, and waits for the callback URI that
// `gpn callback` relays from the browser.
func waitForBrowserLogin(ctx context.Context, listener *relay.Listener, page []byte, timeout time.Duration) (string, error) {
	server, err := loginpage.Start(page)
	if err != nil {
		return "", err
	}
	defer server.Close()

	fmt.Fprintln(os.Stderr, "Opening the browser for login:", server.URL)
	if err := exec.Command("xdg-open", server.URL).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Could not open the browser; open the URL above by hand.")
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	uri, err := listener.Wait(ctx)
	if err != nil {
		return "", fmt.Errorf("waiting for the browser login: %w", err)
	}
	return uri, nil
}

func printStatus(status control.Status) {
	fmt.Println(statusLine(status))
}

func statusLine(status control.Status) string {
	line := status.State
	if status.Gateway != "" {
		line += fmt.Sprintf(" to %s over %s as %s", status.Gateway, status.Transport, status.ClientIP)
	}
	if status.Error != "" {
		line += ": " + status.Error
	}
	return fmt.Sprintf("%s (since %s)", line, status.Since.Format(time.TimeOnly))
}
