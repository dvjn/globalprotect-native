package main

import (
	"fmt"
	"log"
	"os"

	"github.com/dvjn/globalprotect-native/internal/desktop"
)

const usage = `gpn: globalprotect-native, a GlobalProtect client for Linux

Usage:
  gpn <command> [flags]

Commands for the active desktop session and members of the gpn group:
  connect            Connect, logging in through the browser when needed
  disconnect         Disconnect
  reconnect          Rebuild the tunnel now, or connect if it is down
  status             Show the tunnel state
  login              Log in through the browser
  update             Install the latest release with the package manager that installed gpn
  agent              Tray icon, notifications and browser logins for the desktop session
  callback <uri>     Receive a globalprotectcallback: URI from the browser

Commands for root:
  daemon             Serve the control socket and own the tunnel
  cleanup            Remove what a killed daemon left behind
  config             Print the gateway's tunnel configuration
  hip [--send]       Build the HIP report, and send it with --send
  hip --export       Print the HIP profile, to import here or in another client
  hip --preview      Print the report the HIP profile gives, without connecting

  version            Print the version
`

var version = "dev"

// logger writes progress to stderr, which systemd sends to the journal.
var logger = log.New(os.Stderr, "", 0)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	command, args := os.Args[1], os.Args[2:]
	switch command {
	case "connect", "disconnect", "reconnect", "status", "login":
		desktop.SetUp()
	}

	var err error
	switch command {
	case "connect":
		err = runConnect(args)
	case "disconnect":
		err = runDisconnect(args)
	case "reconnect":
		err = runReconnect(args)
	case "status":
		err = runStatus(args)
	case "login":
		err = runLogin(args)
	case "update":
		err = runUpdate(args)
	case "agent":
		err = runAgent(args)
	case "callback":
		err = runCallback(args)
	case "daemon":
		err = runDaemon(args)
	case "cleanup":
		err = runCleanup(args)
	case "config":
		err = runConfig(args)
	case "hip":
		err = runHIP(args)
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", command, usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "gpn:", err)
		os.Exit(1)
	}
}
