package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/dvjn/globalprotect-native/internal/control"
	"github.com/dvjn/globalprotect-native/internal/desktop"
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
	return desktop.BrowserLogin(ctx, *portal)
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
				err := desktop.BrowserLogin(ctx, "")
				if errors.Is(err, relay.ErrLoginPending) {
					fmt.Fprintln(os.Stderr, "Waiting for the login already open in the browser.")
				} else if err != nil {
					return err
				}
			}
		}
	}
}

func printStatus(status control.Status) {
	fmt.Println(status)
}

func runUpdate(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: gpn update")
	}
	response, err := control.Call(control.Request{Command: control.CommandUpdate})
	if err != nil {
		return err
	}
	fmt.Println(response.Update)
	return nil
}
