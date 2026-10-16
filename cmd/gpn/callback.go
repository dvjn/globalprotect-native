package main

import (
	"errors"
	"os"
	"syscall"

	"github.com/dvjn/globalprotect-native/internal/relay"
)

// officialHandler is the command the official client registers for globalprotectcallback: URIs.
var officialHandler = []string{"/usr/bin/globalprotect", "defaultbrowser"}

func runCallback(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: gpn callback <uri>")
	}
	uri := args[0]

	socketPath, err := relay.SocketPath()
	if err != nil {
		return err
	}
	err = relay.Send(socketPath, uri)
	if !errors.Is(err, relay.ErrNoListener) {
		return err
	}
	return syscall.Exec(officialHandler[0], append(officialHandler, uri), os.Environ())
}
