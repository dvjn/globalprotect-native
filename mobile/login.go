package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/loginpage"
)

// loginRequestTimeout bounds each request to the portal during a login.
const loginRequestTimeout = time.Minute

// Login is a browser login in progress: the portal's SAML form, served on localhost.
type Login struct {
	portal *gp.Client
	page   *loginpage.Server
}

// StartLogin asks portal how to log in and serves its SAML form on localhost. identityJSON is
// the "identity" object of Start's settings. The app opens URL in a Custom Tab and, when the
// browser opens a globalprotectcallback: URI, passes it to Finish.
func StartLogin(portal, identityJSON string, app App) (*Login, error) {
	var device identity
	if err := json.Unmarshal([]byte(identityJSON), &device); err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	client := portalClient(portal, device, app)
	ctx, cancel := context.WithTimeout(context.Background(), loginRequestTimeout)
	defer cancel()
	prelogin, err := client.PortalPrelogin(ctx)
	if err != nil {
		return nil, err
	}
	if !prelogin.UsesCAS() {
		return nil, errors.New("portal does not use Cloud Authentication; only CAS login is supported")
	}
	form, err := prelogin.LoginPage()
	if err != nil {
		return nil, err
	}
	page, err := loginpage.Start(form)
	if err != nil {
		return nil, err
	}
	return &Login{portal: client, page: page}, nil
}

// portalClient connects outside the VPN, so a login works while a tunnel is up.
func portalClient(portal string, device identity, app App) *gp.Client {
	client := gp.NewClient(portal, device.gp())
	client.UseDialer(protectedDialer(app))
	return client
}

// URL is the login page to open in the browser.
func (login *Login) URL() string {
	return login.page.URL
}

// Finish exchanges callbackURI, the globalprotectcallback: URI the browser opened, for the
// portal's login cookies, and returns them as the "credential" JSON of Start's settings. The
// app keeps it, encrypted, until the portal rejects it.
func (login *Login) Finish(callbackURI string) (string, error) {
	defer login.Close()
	callback, err := gp.ParseCallback(callbackURI)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), loginRequestTimeout)
	defer cancel()
	portalConfig, _, err := login.portal.PortalGetConfig(ctx, gp.Credential{Username: callback.Username, Token: callback.Token})
	if err != nil {
		return "", err
	}
	saved, err := json.Marshal(credential{
		Username:               callback.Username,
		UserAuthCookie:         portalConfig.UserAuthCookie,
		PrelogonUserAuthCookie: portalConfig.PrelogonUserAuthCookie,
	})
	return string(saved), err
}

// Close stops serving the login page.
func (login *Login) Close() {
	login.page.Close()
}

// Gateways lists the portal's gateways for the app to offer a choice, as JSON such as
// [{"name": "India South", "address": "gw.example.com"}]. credentialJSON is what Finish
// returned.
func Gateways(portal, identityJSON, credentialJSON string, app App) (string, error) {
	var device identity
	if err := json.Unmarshal([]byte(identityJSON), &device); err != nil {
		return "", fmt.Errorf("identity: %w", err)
	}
	var saved credential
	if err := json.Unmarshal([]byte(credentialJSON), &saved); err != nil {
		return "", fmt.Errorf("credential: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), loginRequestTimeout)
	defer cancel()
	portalConfig, _, err := portalClient(portal, device, app).PortalGetConfig(ctx, gp.Credential{
		Username:               saved.Username,
		UserAuthCookie:         saved.UserAuthCookie,
		PrelogonUserAuthCookie: saved.PrelogonUserAuthCookie,
	})
	if err != nil {
		return "", err
	}
	type choice struct {
		Name    string `json:"name"`
		Address string `json:"address"`
	}
	choices := []choice{}
	for _, gateway := range portalConfig.Gateways {
		choices = append(choices, choice{Name: gateway.Name, Address: gateway.Address})
	}
	listed, err := json.Marshal(choices)
	return string(listed), err
}
