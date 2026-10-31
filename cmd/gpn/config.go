package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/dvjn/globalprotect-native/internal/engine"
	"github.com/dvjn/globalprotect-native/internal/gp"
)

// runConfig prints the configured gateway's tunnel configuration. It reads the daemon's files,
// so it runs as root.
func runConfig(args []string) error {
	flags := flag.NewFlagSet("config", flag.ExitOnError)
	loadProfile := profileFlags(flags)
	captureDir := flags.String("capture", "", "write the redacted gateway config XML to this directory")
	keepSession := flags.Bool("keep-session", false, "do not log out of the gateway afterwards")
	flags.Parse(args)
	profile, err := loadProfile()
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
	if !*keepSession {
		defer opened.LogOut()
	}

	config, raw, err := opened.Client.GatewayGetConfig(ctx, opened.Session)
	if *captureDir != "" && raw != nil {
		if err := writeCapture(*captureDir, "gateway-config.xml", raw); err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}

	fmt.Printf("Gateway: %s (%s)\n", opened.Gateway.Name, opened.Gateway.Address)
	printGatewayConfig(config)
	return nil
}

func printGatewayConfig(config gp.GatewayConfig) {
	fmt.Printf("Client IP: %s/%s\n", config.ClientIP, config.Netmask)
	if config.ClientIPv6 != "" {
		fmt.Printf("Client IPv6: %s\n", config.ClientIPv6)
	}
	fmt.Printf("Gateway address: %s\n", config.GatewayAddress)
	fmt.Printf("Quarantined: %t\n", config.Quarantined)
	fmt.Printf("MTU: %d\n", config.MTU)
	fmt.Printf("Lifetime: %d s, idle timeout: %d s, HIP interval: %d s\n", config.LifetimeSeconds, config.IdleTimeout, config.HIPReportInterval)
	fmt.Printf("SSL tunnel path: %s\n", config.SSLTunnelPath)
	printList("DNS servers", config.DNSServers)
	printList("DNS suffixes", config.DNSSuffixes)
	printList("Include routes", config.IncludeRoutes)
	printList("Exclude routes", config.ExcludeRoutes)
	printList("Include domains", config.IncludeDomains)
	printList("Exclude domains", config.ExcludeDomains)

	if config.ESP == nil {
		fmt.Println("ESP: not offered")
		return
	}
	esp := config.ESP
	fmt.Printf("ESP: UDP %d, %s, %s with %s\n", esp.UDPPort, esp.Mode, esp.Encryption, esp.Integrity)
	for _, direction := range []struct {
		name string
		keys gp.ESPKeys
	}{{"client to server", esp.ClientToServer}, {"server to client", esp.ServerToClient}} {
		fmt.Printf("  %s: SPI set, encryption key %d bits, integrity key %d bits\n",
			direction.name, len(direction.keys.EncryptionKey)*8, len(direction.keys.IntegrityKey)*8)
	}
}

func printList(title string, items []string) {
	fmt.Printf("%s (%d):\n", title, len(items))
	for _, item := range items {
		fmt.Printf("  %s\n", item)
	}
}

func writeCapture(dir, name string, raw []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, gp.Redact(raw), 0o600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Wrote", path)
	return nil
}
