package profile

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/state"
)

func testProfile(t *testing.T, settings config.Config) Profile {
	return Profile{
		Settings:  settings,
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Identify: func(_ config.Config, hostID string) (gp.Identity, error) {
			return gp.Identity{HostID: hostID}, nil
		},
	}
}

func TestLoginNeedsAPortal(t *testing.T) {
	profile := testProfile(t, config.Default())
	if profile.PortalKnown() {
		t.Error("PortalKnown without a portal")
	}
	if _, err := profile.Login(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("got %v, want ErrNotConfigured", err)
	}
}

func TestLoginNeedsACookie(t *testing.T) {
	profile := testProfile(t, config.Default())
	if err := profile.SaveChoice("vpn.example.com", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.Login(); !errors.Is(err, gp.ErrAuthenticationRejected) {
		t.Errorf("got %v, want gp.ErrAuthenticationRejected", err)
	}
}

func TestLoginUsesSettingsOverChoice(t *testing.T) {
	settings := config.Default()
	settings.Gateway = "configured"
	profile := testProfile(t, settings)
	if err := profile.SaveChoice("vpn.example.com", "chosen"); err != nil {
		t.Fatal(err)
	}
	saved, err := state.Load(profile.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	saved.Portals["vpn.example.com"] = state.PortalCookie{Username: "user", UserAuthCookie: "cookie"}
	if err := saved.Save(profile.StatePath); err != nil {
		t.Fatal(err)
	}

	login, err := profile.Login()
	if err != nil {
		t.Fatal(err)
	}
	if login.Portal != "vpn.example.com" || login.Gateway != "configured" {
		t.Errorf("got portal %q gateway %q, want vpn.example.com and configured", login.Portal, login.Gateway)
	}
	if login.Credential.UserAuthCookie != "cookie" || login.Identity.HostID != saved.HostID {
		t.Errorf("got credential %+v identity %+v", login.Credential, login.Identity)
	}
}

func TestSaveChoiceForgetsGatewayOfOldPortal(t *testing.T) {
	profile := testProfile(t, config.Default())
	if err := profile.SaveChoice("one.example.com", "east"); err != nil {
		t.Fatal(err)
	}
	if err := profile.SaveChoice("two.example.com", ""); err != nil {
		t.Fatal(err)
	}
	saved, err := state.Load(profile.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Portal != "two.example.com" || saved.Gateway != "" {
		t.Errorf("got portal %q gateway %q, want two.example.com and the fastest", saved.Portal, saved.Gateway)
	}
}
