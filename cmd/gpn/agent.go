package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/dvjn/globalprotect-native/internal/desktop"
)

// runAgent runs the desktop session's agent: tray icon, notifications and browser logins.
func runAgent(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: gpn agent")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	desktop.RunAgent(ctx)
	return nil
}
