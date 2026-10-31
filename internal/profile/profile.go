// Package profile is what gpn knows about where and as whom to connect: the settings, the saved
// state with the user's portal choice and login, and the machine's identity.
package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/engine"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/hip"
	"github.com/dvjn/globalprotect-native/internal/state"
)

// Profile is the settings and the state file, with how to describe the machine to the portal.
type Profile struct {
	Settings  config.Config
	StatePath string
	// Identify describes the machine. hostID is the random one saved in the state.
	Identify func(settings config.Config, hostID string) (gp.Identity, error)
}

// ErrNotConfigured means no portal is known yet; retrying cannot help.
var ErrNotConfigured = engine.Permanent(errors.New("not configured"))

// target is the portal and gateway to use: the settings file's, or else the user's saved choice.
// An empty gateway means the fastest one. Without a portal, nothing can start, but the daemon
// still runs, so a fresh install works and `gpn connect` can say what is missing.
func (profile Profile) target(saved *state.State) (portal, gateway string, err error) {
	portal, gateway = profile.Settings.Portal, profile.Settings.Gateway
	if portal == "" {
		portal = saved.Portal
	}
	if gateway == "" {
		gateway = saved.Gateway
	}
	if portal == "" {
		return "", "", fmt.Errorf("%w: run `gpn connect --portal HOST` once", ErrNotConfigured)
	}
	return portal, gateway, nil
}

// PortalKnown reports whether the settings or a user's saved choice name a portal.
func (profile Profile) PortalKnown() bool {
	saved, err := state.Load(profile.StatePath)
	if err != nil {
		return false
	}
	_, _, err = profile.target(saved)
	return err == nil
}

// SaveChoice records the portal and gateway a user picked; empty values keep the old choice.
func (profile Profile) SaveChoice(portal, gateway string) error {
	if portal == "" && gateway == "" {
		return nil
	}
	saved, err := state.Load(profile.StatePath)
	if err != nil {
		return err
	}
	if portal != "" && portal != saved.Portal {
		saved.Portal = portal
		saved.Gateway = ""
	}
	if gateway != "" {
		saved.Gateway = gateway
	}
	return saved.Save(profile.StatePath)
}

// portalClient is a client for the configured portal, with the machine identity.
func (profile Profile) portalClient() (*gp.Client, *state.State, error) {
	saved, err := state.Load(profile.StatePath)
	if err != nil {
		return nil, nil, err
	}
	portal, _, err := profile.target(saved)
	if err != nil {
		return nil, nil, err
	}
	identity, err := profile.Identify(profile.Settings, saved.HostID)
	if err != nil {
		return nil, nil, err
	}
	override, err := profile.hipOverride()
	if err != nil {
		return nil, nil, err
	}
	return gp.NewClient(portal, engine.WithHIPProfile(identity, override)), saved, nil
}

// Login is what the engine needs to open a gateway session: the portal with its saved cookie,
// and the chosen gateway. A missing cookie comes back as gp.ErrAuthenticationRejected.
func (profile Profile) Login() (engine.Login, error) {
	portal, saved, err := profile.portalClient()
	if err != nil {
		return engine.Login{}, err
	}
	_, gatewayName, err := profile.target(saved)
	if err != nil {
		return engine.Login{}, err
	}
	cookie, found := saved.Portals[portal.Server]
	if !found {
		return engine.Login{}, fmt.Errorf("not logged in to %s: %w", portal.Server, gp.ErrAuthenticationRejected)
	}
	override, err := profile.hipOverride()
	if err != nil {
		return engine.Login{}, err
	}
	// portal.Identity has the override already; applying it again changes nothing.
	return engine.Login{
		Portal:   portal.Server,
		Gateway:  gatewayName,
		Identity: portal.Identity,
		HIP:      override,
		Credential: gp.Credential{
			Username:               cookie.Username,
			UserAuthCookie:         cookie.UserAuthCookie,
			PrelogonUserAuthCookie: cookie.PrelogonUserAuthCookie,
		},
	}, nil
}

// hipOverride is the HIP profile the settings import, if any.
func (profile Profile) hipOverride() (hip.Profile, error) {
	var override hip.Profile
	if profile.Settings.HIP.Profile == "" {
		return override, nil
	}
	text, err := os.ReadFile(profile.Settings.HIP.Profile)
	if err != nil {
		return override, fmt.Errorf("HIP profile: %w", err)
	}
	if err := json.Unmarshal(text, &override); err != nil {
		return override, fmt.Errorf("HIP profile %s: %w", profile.Settings.HIP.Profile, err)
	}
	return override, nil
}

// HIPProfile is what the HIP report says about this machine with platform, for exporting, and
// the saved login's username, if any. No login is needed.
func (profile Profile) HIPProfile(platform engine.Platform) (hip.Profile, string, error) {
	saved, err := state.Load(profile.StatePath)
	if err != nil {
		return hip.Profile{}, "", err
	}
	identity, err := profile.Identify(profile.Settings, saved.HostID)
	if err != nil {
		return hip.Profile{}, "", err
	}
	override, err := profile.hipOverride()
	if err != nil {
		return hip.Profile{}, "", err
	}
	username := ""
	if portal, _, err := profile.target(saved); err == nil {
		username = saved.Portals[portal].Username
	}
	return engine.HIPProfile(identity, username, platform, override), username, nil
}

// LoginPage returns the portal's SAML page to open in a browser, and how long the login may take.
func (profile Profile) LoginPage(ctx context.Context) ([]byte, time.Duration, error) {
	portal, _, err := profile.portalClient()
	if err != nil {
		return nil, 0, err
	}
	prelogin, err := portal.PortalPrelogin(ctx)
	if err != nil {
		return nil, 0, err
	}
	if !prelogin.UsesCAS() {
		return nil, 0, errors.New("portal does not use Cloud Authentication; only CAS login is supported")
	}
	page, err := prelogin.LoginPage()
	return page, prelogin.LoginTimeout(), err
}

// SaveLogin exchanges the browser's token for a portal cookie and saves it. It returns the portal.
func (profile Profile) SaveLogin(ctx context.Context, username, token string) (string, error) {
	portal, saved, err := profile.portalClient()
	if err != nil {
		return "", err
	}
	portalConfig, _, err := portal.PortalGetConfig(ctx, gp.Credential{Username: username, Token: token})
	if err != nil {
		return "", err
	}
	saved.Portals[portal.Server] = state.PortalCookie{
		Username:               username,
		UserAuthCookie:         portalConfig.UserAuthCookie,
		PrelogonUserAuthCookie: portalConfig.PrelogonUserAuthCookie,
		SavedAt:                time.Now(),
	}
	return portal.Server, saved.Save(profile.StatePath)
}
