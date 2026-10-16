package main

import (
	"context"

	"github.com/godbus/dbus/v5"
)

const logind = "org.freedesktop.login1"

// watchResume calls onResume each time systemd-logind reports that the machine woke up,
// until ctx ends. It fails on systems without logind.
func watchResume(ctx context.Context, onResume func()) error {
	bus, err := dbus.ConnectSystemBus()
	if err != nil {
		return err
	}
	defer bus.Close()

	// Matching the sender keeps another process from faking a resume.
	if err := bus.AddMatchSignal(
		dbus.WithMatchSender(logind),
		dbus.WithMatchInterface(logind+".Manager"),
		dbus.WithMatchMember("PrepareForSleep"),
	); err != nil {
		return err
	}
	signals := make(chan *dbus.Signal, 4)
	bus.Signal(signals)

	for {
		select {
		case <-ctx.Done():
			return nil
		case message := <-signals:
			if len(message.Body) != 1 {
				continue
			}
			if goingToSleep, ok := message.Body[0].(bool); ok && !goingToSleep {
				onResume()
			}
		}
	}
}
