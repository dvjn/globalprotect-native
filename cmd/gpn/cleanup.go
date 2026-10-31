package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/dvjn/globalprotect-native/internal/daemon"
	"github.com/dvjn/globalprotect-native/internal/platform/linux"
)

// runCleanup removes what a killed daemon left behind, so the network works again without it.
func runCleanup(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: gpn cleanup")
	}
	if os.Geteuid() != 0 {
		return errors.New("cleanup changes network settings; run it as root")
	}
	lock, err := daemon.Lock()
	if err != nil {
		return fmt.Errorf("%w; stop it instead, it cleans up after itself", err)
	}
	defer lock.Close()
	return linux.RemoveLeftovers()
}
