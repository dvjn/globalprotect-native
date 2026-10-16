package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/dvjn/globalprotect-native/internal/hip"
	"github.com/dvjn/globalprotect-native/internal/userdir"
)

// runHIP builds the HIP report for the configured gateway, and sends it with --send.
// It reads the daemon's files, so it runs as root.
func runHIP(args []string) error {
	flags := flag.NewFlagSet("hip", flag.ExitOnError)
	loadEnvironment := environmentFlags(flags)
	send := flags.Bool("send", false, "submit the report to the gateway instead of only printing it")
	flags.Parse(args)
	env, err := loadEnvironment()
	if err != nil {
		return err
	}
	home, err := userdir.Home()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	opened, err := openGatewaySession(ctx, env)
	if err != nil {
		return err
	}
	defer opened.logOut()

	gatewayConfig, _, err := opened.client.GatewayGetConfig(ctx, opened.session)
	if err != nil {
		return err
	}
	needed, err := opened.client.HIPReportNeeded(ctx, opened.session, gatewayConfig.ClientIP)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Gateway %s wants a HIP report: %t\n", opened.gateway.Name, needed)

	report, err := buildHIPReport(opened, gatewayConfig.ClientIP, home)
	if err != nil {
		return err
	}
	fmt.Println(string(report))

	if !*send {
		fmt.Fprintln(os.Stderr, "Not sent; pass --send to submit it.")
		return nil
	}
	if err := opened.client.SubmitHIPReport(ctx, opened.session, gatewayConfig.ClientIP, report); err != nil {
		return err
	}
	needed, err = opened.client.HIPReportNeeded(ctx, opened.session, gatewayConfig.ClientIP)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Report accepted. Gateway still wants a report: %t\n", needed)
	return nil
}

// buildHIPReport describes this machine. userHome is reported as a drive next to "/".
func buildHIPReport(opened gatewaySession, clientIP, userHome string) ([]byte, error) {
	sessionDomain := opened.session.Domain
	if sessionDomain == "(empty_domain)" {
		sessionDomain = ""
	}
	_, emailDomain, _ := strings.Cut(opened.session.Username, "@")

	drives := []string{"/"}
	if userHome != "" {
		drives = append(drives, userHome)
	}
	return hip.Build(hip.Input{
		MD5:           opened.session.HIPToken(),
		Username:      opened.session.Username,
		Domain:        sessionDomain,
		HostDomain:    emailDomain,
		Computer:      opened.session.Computer,
		HostID:        opened.identity.HostID,
		ClientIP:      clientIP,
		ClientVersion: opened.identity.ClientVersion,
		OS:            opened.identity.OSVersion,
		Products:      hip.DetectProducts(),
		Facts:         hip.CollectFacts(drives),
		Now:           time.Now(),
	})
}

// sendHIPReportIfNeeded submits a report when the gateway asks for one.
func sendHIPReportIfNeeded(ctx context.Context, opened gatewaySession, clientIP, userHome string) error {
	needed, err := opened.client.HIPReportNeeded(ctx, opened.session, clientIP)
	if err != nil || !needed {
		return err
	}
	report, err := buildHIPReport(opened, clientIP, userHome)
	if err != nil {
		return err
	}
	if err := opened.client.SubmitHIPReport(ctx, opened.session, clientIP, report); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Sent the HIP report.")
	return nil
}
