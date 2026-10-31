package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/dvjn/globalprotect-native/internal/engine"
	"github.com/dvjn/globalprotect-native/internal/platform/linux"
	"github.com/dvjn/globalprotect-native/internal/userdir"
)

// runHIP builds the HIP report for the configured gateway, and sends it with --send.
// It reads the daemon's files, so it runs as root.
func runHIP(args []string) error {
	flags := flag.NewFlagSet("hip", flag.ExitOnError)
	loadProfile := profileFlags(flags)
	send := flags.Bool("send", false, "submit the report to the gateway instead of only printing it")
	flags.Parse(args)
	profile, err := loadProfile()
	if err != nil {
		return err
	}
	home, err := userdir.Home()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	login, err := profile.Login()
	if err != nil {
		return err
	}
	opened, err := engine.OpenSession(ctx, login, nil, logger)
	if err != nil {
		return err
	}
	defer opened.LogOut()

	gatewayConfig, _, err := opened.Client.GatewayGetConfig(ctx, opened.Session)
	if err != nil {
		return err
	}
	needed, err := opened.Client.HIPReportNeeded(ctx, opened.Session, gatewayConfig.ClientIP)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Gateway %s wants a HIP report: %t\n", opened.Gateway.Name, needed)

	report, err := engine.BuildHIPReport(opened, gatewayConfig.ClientIP, linux.Platform{UserHome: home, Log: logger})
	if err != nil {
		return err
	}
	fmt.Println(string(report))

	if !*send {
		fmt.Fprintln(os.Stderr, "Not sent; pass --send to submit it.")
		return nil
	}
	if err := opened.Client.SubmitHIPReport(ctx, opened.Session, gatewayConfig.ClientIP, report); err != nil {
		return err
	}
	needed, err = opened.Client.HIPReportNeeded(ctx, opened.Session, gatewayConfig.ClientIP)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Report accepted. Gateway still wants a report: %t\n", needed)
	return nil
}
