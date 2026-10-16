package gp

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
)

// Session is a gateway login. Its fields go with every later gateway request.
type Session struct {
	Username    string
	AuthCookie  string
	Portal      string
	Domain      string
	PreferredIP string
	Computer    string
}

func (session Session) formValues() url.Values {
	return url.Values{
		"user":         {session.Username},
		"authcookie":   {session.AuthCookie},
		"portal":       {session.Portal},
		"domain":       {session.Domain},
		"preferred-ip": {session.PreferredIP},
		"computer":     {session.Computer},
	}
}

// Positions of the values gpn needs in the <argument> list of a login.esp response.
// See gp_login_args in OpenConnect's auth-globalprotect.c.
const (
	argumentAuthCookie     = 1
	argumentPortal         = 3
	argumentUser           = 4
	argumentDomain         = 7
	argumentConnectionType = 12
	argumentPreferredIP    = 15
)

// ParseGatewayLogin decodes a login.esp response into a session.
func ParseGatewayLogin(body []byte, computer string) (Session, error) {
	var response struct {
		XMLName   xml.Name
		Error     string   `xml:"error"`
		Arguments []string `xml:"application-desc>argument"`
	}
	if err := xml.Unmarshal(body, &response); err != nil {
		return Session{}, fmt.Errorf("parse gateway login: %w", err)
	}
	if response.XMLName.Local != "jnlp" {
		return Session{}, fmt.Errorf("gateway login failed: %s", response.Error)
	}

	argument := func(position int) string {
		if position >= len(response.Arguments) {
			return ""
		}
		value := strings.TrimSpace(response.Arguments[position])
		if value == "(null)" {
			return ""
		}
		value, _ = url.QueryUnescape(value)
		return value
	}

	if connectionType := argument(argumentConnectionType); connectionType != "tunnel" {
		return Session{}, fmt.Errorf("gateway login returned connection type %q, want tunnel", connectionType)
	}
	session := Session{
		Username:    argument(argumentUser),
		AuthCookie:  argument(argumentAuthCookie),
		Portal:      argument(argumentPortal),
		Domain:      argument(argumentDomain),
		PreferredIP: argument(argumentPreferredIP),
		Computer:    computer,
	}
	if session.AuthCookie == "" || session.Username == "" {
		return Session{}, fmt.Errorf("gateway login returned no auth cookie or user")
	}
	return session, nil
}

// GatewayLogin exchanges the portal cookie for a gateway session.
func (client *Client) GatewayLogin(ctx context.Context, credential Credential) (Session, error) {
	form := client.Identity.formValues()
	form.Set("jnlpReady", "jnlpReady")
	form.Set("ok", "Login")
	form.Set("direct", "yes")
	form.Set("prot", "https:")
	form.Set("internal", "no")
	form.Set("server", client.Server)
	form.Set("user", credential.Username)
	form.Set("passwd", samlPassword)
	form.Set("prelogin-cookie", "")
	form.Set("portal-userauthcookie", orEmptyCookie(credential.UserAuthCookie))
	form.Set("portal-prelogonuserauthcookie", orEmptyCookie(credential.PrelogonUserAuthCookie))
	form.Set("inputStr", "")

	body, err := client.post(ctx, "/ssl-vpn/login.esp", form)
	if err != nil {
		return Session{}, err
	}
	return ParseGatewayLogin(body, client.Identity.Computer)
}

// GatewayLogout ends the session, so the gateway frees its IP address.
func (client *Client) GatewayLogout(ctx context.Context, session Session) error {
	body, err := client.post(ctx, "/ssl-vpn/logout.esp", session.formValues())
	if err != nil {
		return err
	}
	if err := checkResponseStatus(body); err != nil {
		return fmt.Errorf("gateway logout: %w", err)
	}
	return nil
}

// GatewayGetConfig fetches the tunnel configuration and returns it with the raw response.
func (client *Client) GatewayGetConfig(ctx context.Context, session Session) (GatewayConfig, []byte, error) {
	form := session.formValues()
	form.Set("client-type", "1")
	form.Set("protocol-version", "p1")
	form.Set("internal", "no")
	form.Set("app-version", client.Identity.ClientVersion)
	form.Set("ipv6-support", "yes")
	form.Set("clientos", "Linux")
	form.Set("os-version", client.Identity.OSVersion)
	form.Set("enc-algo", "aes-256-gcm,aes-128-gcm,aes-256-cbc,aes-128-cbc")
	form.Set("hmac-algo", "sha1,sha256,md5")

	body, err := client.post(ctx, "/ssl-vpn/getconfig.esp", form)
	if err != nil {
		return GatewayConfig{}, nil, err
	}
	config, err := ParseGatewayConfig(body)
	return config, body, err
}

func checkResponseStatus(body []byte) error {
	var response struct {
		Status string `xml:"status,attr"`
		Error  string `xml:"error"`
	}
	if err := xml.Unmarshal(body, &response); err != nil {
		return err
	}
	if response.Status != "success" {
		return fmt.Errorf("status %q: %s", response.Status, response.Error)
	}
	return nil
}
