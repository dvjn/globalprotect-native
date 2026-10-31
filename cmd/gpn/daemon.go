package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/dvjn/globalprotect-native/internal/control"
	"github.com/dvjn/globalprotect-native/internal/daemon"
)

// runDaemon serves the control socket and owns the tunnel. It runs as root.
func runDaemon(args []string) error {
	flags := flag.NewFlagSet("daemon", flag.ExitOnError)
	loadProfile := profileFlags(flags)
	socketPath := flags.String("socket", control.DefaultSocket, "control socket")
	groupName := flags.String("group", "gpn", "group whose members may control the daemon from any session")
	flags.Parse(args)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return daemon.Run(ctx, daemon.Options{
		Socket:      *socketPath,
		Group:       *groupName,
		LoadProfile: loadProfile,
		Version:     version,
		Log:         logger,
	})
}
