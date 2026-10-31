// Package mobile is the Go core of the Android app: it runs the engine with the app's
// VpnService as its platform. gomobile binds it, so its API uses only the types gomobile
// supports: strings, numbers, booleans, byte slices, errors, interfaces and struct pointers.
// Structured input that would need anything else is JSON.
package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/control"
	"github.com/dvjn/globalprotect-native/internal/engine"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/hip"
)

// App is what the Android app provides, implemented in Kotlin.
type App interface {
	// Protect keeps the socket fd outside the VPN, as VpnService.protect does, and reports
	// whether it could.
	Protect(fd int) bool
	// Establish creates the VPN device with VpnService.Builder and returns its file
	// descriptor, detached: Go closes it when the tunnel ends.
	Establish(tunnel *TunnelConfig) (int, error)
	// DNSServer is a DNS server of the network outside the VPN, which looks up the portal
	// and gateways; "" uses Go's default resolver.
	DNSServer() string
	// HIPProfile is what the app detects for the HIP report, as HIP profile JSON such as
	// {"os_vendor": "Google", "products": [{"category": "anti-malware", "vendor": "…",
	// "name": "…", "version": "…", "state": "yes"}], "drives": [{"name": "/data",
	// "encrypted": true}], "interfaces": [{"name": "wlan0", "mac": "…", "ipv4": ["…"]}]}.
	// Fields it leaves out come from the identity; "" detects nothing.
	HIPProfile() string
	// Log receives one line of progress.
	Log(message string)
}

// TunnelConfig is what the VPN device needs. Lists are separated by commas.
type TunnelConfig struct {
	ClientIP string
	MTU      int
	// Routes go through the tunnel, except for ExcludeRoutes, which need Android 13.
	Routes        string
	ExcludeRoutes string
	DNSServers    string
	SearchDomains string
	// IncludeOnly sends only Routes through the tunnel; Domains then name what should go
	// through it, and otherwise what should not. Android cannot route by name yet, so the
	// app may only use them for DNS.
	IncludeOnly bool
	Domains     string
}

// Status is the tunnel's state, one of the control.State constants, such as "connected".
type Status struct {
	State     string
	Gateway   string
	ClientIP  string
	Transport string
	Error     string
}

// Listener hears about every change of the tunnel's state.
type Listener interface {
	OnStatus(status *Status)
}

// settings is the JSON that Start takes: where to connect, as whom, and how.
type settings struct {
	Portal string `json:"portal"`
	// Gateway is a gateway's name or address, or "" for the fastest.
	Gateway    string     `json:"gateway"`
	Credential credential `json:"credential"`
	Identity   identity   `json:"identity"`
	SSLOnly    bool       `json:"ssl_only"`
	SendHIP    bool       `json:"send_hip"`
	// ExcludeDomains, IncludeDomains and IncludeRoutes work as in the Linux config file.
	ExcludeDomains []string `json:"exclude_domains"`
	IncludeDomains []string `json:"include_domains"`
	IncludeRoutes  []string `json:"include_routes"`
	// HIPProfile, exported by any client, is reported instead of what the app detects.
	HIPProfile hip.Profile `json:"hip_profile"`
}

func parseSettings(settingsJSON string) (settings, error) {
	var parsed settings
	if err := json.Unmarshal([]byte(settingsJSON), &parsed); err != nil {
		return settings{}, fmt.Errorf("settings: %w", err)
	}
	return parsed, nil
}

// credential is the saved portal login, from Login.Finish.
type credential struct {
	Username               string `json:"username"`
	UserAuthCookie         string `json:"user_auth_cookie"`
	PrelogonUserAuthCookie string `json:"prelogon_user_auth_cookie"`
}

// identity describes the device to the portal.
type identity struct {
	HostID        string `json:"host_id"`
	SerialNumber  string `json:"serial_number"`
	Computer      string `json:"computer"`
	OSVersion     string `json:"os_version"`
	ClientVersion string `json:"client_version"`
}

func (device identity) gp() gp.Identity {
	return gp.Identity(device)
}

// Tunnel is a running tunnel, kept up until Stop.
type Tunnel struct {
	stop       context.CancelFunc
	done       chan struct{}
	supervisor *engine.Supervisor
}

// Start connects with settingsJSON, which holds:
//
//	{"portal": "vpn.example.com", "gateway": "", "ssl_only": false, "send_hip": true,
//	 "credential": {"username": "…", "user_auth_cookie": "…", "prelogon_user_auth_cookie": "…"},
//	 "identity": {"host_id": "…", "serial_number": "…", "computer": "…", "os_version": "…", "client_version": "…"},
//	 "exclude_domains": [], "include_domains": [], "include_routes": [], "hip_profile": {…}}
//
// It keeps the tunnel up until Stop, telling listener about every change. When the portal
// rejects the saved login, the tunnel stops in state "needs-login"; log in again and start a
// new one.
func Start(settingsJSON string, app App, listener Listener) (*Tunnel, error) {
	settings, err := parseSettings(settingsJSON)
	if err != nil {
		return nil, err
	}
	if settings.Portal == "" {
		return nil, fmt.Errorf("settings: no portal")
	}
	login := engine.Login{
		Portal:   settings.Portal,
		Gateway:  settings.Gateway,
		Identity: settings.Identity.gp(),
		Credential: gp.Credential{
			Username:               settings.Credential.Username,
			UserAuthCookie:         settings.Credential.UserAuthCookie,
			PrelogonUserAuthCookie: settings.Credential.PrelogonUserAuthCookie,
		},
		HIP: settings.HIPProfile,
	}
	engineSettings := config.Config{
		SSLOnly:        settings.SSLOnly,
		ExcludeDomains: settings.ExcludeDomains,
		IncludeDomains: settings.IncludeDomains,
		IncludeRoutes:  settings.IncludeRoutes,
		HIP:            config.HIP{Send: settings.SendHIP},
	}

	logger := log.New(appLog{app}, "", 0)
	ctx, stop := context.WithCancel(context.Background())
	tunnel := &Tunnel{stop: stop, done: make(chan struct{})}
	tunnel.supervisor = &engine.Supervisor{
		Prepare: func() (engine.Login, config.Config, error) {
			return login, engineSettings, nil
		},
		Platform: newPlatform(app),
		Log:      logger,
		OnConnected: func(connected engine.Connected) {
			listener.OnStatus(&Status{
				State:     control.StateConnected,
				Gateway:   connected.Gateway,
				ClientIP:  connected.ClientIP,
				Transport: connected.Transport,
			})
		},
		OnReconnecting: func(reason string) {
			listener.OnStatus(&Status{State: control.StateReconnecting, Error: reason})
		},
	}

	listener.OnStatus(&Status{State: control.StateConnecting})
	go func() {
		defer close(tunnel.done)
		listener.OnStatus(finalStatus(tunnel.supervisor.Run(ctx)))
	}()
	return tunnel, nil
}

func finalStatus(err error) *Status {
	switch {
	case err == nil:
		return &Status{State: control.StateDisconnected}
	case engine.NeedsLogin(err):
		return &Status{State: control.StateNeedsLogin, Error: err.Error()}
	}
	return &Status{State: control.StateFailed, Error: err.Error()}
}

// Restart builds the tunnel again at once, as when the device's network changed.
func (tunnel *Tunnel) Restart() {
	tunnel.supervisor.Restart()
}

// Stop ends the tunnel and waits until it has logged out and closed the VPN device.
func (tunnel *Tunnel) Stop() {
	tunnel.stop()
	<-tunnel.done
}

// appLog sends log lines to App.Log.
type appLog struct{ app App }

func (writer appLog) Write(line []byte) (int, error) {
	writer.app.Log(strings.TrimSuffix(string(line), "\n"))
	return len(line), nil
}

// ExportHIPProfile is the HIP profile the app reports with settingsJSON, Start's settings, as
// JSON that this or any other client can import: what it detects, with the identity and the
// imported profile in place. No login is needed.
func ExportHIPProfile(settingsJSON string, app App) (string, error) {
	profile, _, err := describe(settingsJSON, app)
	if err != nil {
		return "", err
	}
	exported, err := json.MarshalIndent(profile, "", "  ")
	return string(exported), err
}

// PreviewHIPReport is the HIP report the app sends with settingsJSON, with placeholders for
// what each session sets.
func PreviewHIPReport(settingsJSON string, app App) (string, error) {
	profile, username, err := describe(settingsJSON, app)
	if err != nil {
		return "", err
	}
	report, err := engine.PreviewHIPReport(profile, username)
	return string(report), err
}

func describe(settingsJSON string, app App) (hip.Profile, string, error) {
	settings, err := parseSettings(settingsJSON)
	if err != nil {
		return hip.Profile{}, "", err
	}
	username := settings.Credential.Username
	return engine.HIPProfile(settings.Identity.gp(), username, newPlatform(app), settings.HIPProfile), username, nil
}
