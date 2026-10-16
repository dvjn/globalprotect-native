package gp

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"
)

// Credential authenticates a portal getconfig request.
// A fresh login carries Token; a later login carries the cookies saved from the first.
type Credential struct {
	Username               string
	Token                  string
	UserAuthCookie         string
	PrelogonUserAuthCookie string
}

// Gateway is one gateway offered by the portal.
type Gateway struct {
	Name          string
	Address       string
	PriorityRules []PriorityRule
}

// PriorityRule is the gateway priority for clients in one source region, such as "IN" or "Any".
type PriorityRule struct {
	Region   string
	Priority int
}

// PortalConfig is the part of the portal configuration gpn uses.
type PortalConfig struct {
	UserAuthCookie         string
	PrelogonUserAuthCookie string
	ConnectMethod          string
	HIPReportInterval      int
	Gateways               []Gateway
}

type portalConfigXML struct {
	UserAuthCookie         string `xml:"portal-userauthcookie"`
	PrelogonUserAuthCookie string `xml:"portal-prelogonuserauthcookie"`
	ConnectMethod          string `xml:"connect-method"`
	HIPReportInterval      int    `xml:"hip-collection>hip-report-interval"`
	Gateways               []struct {
		Name          string `xml:"name,attr"`
		Description   string `xml:"description"`
		PriorityRules []struct {
			Region   string `xml:"name,attr"`
			Priority int    `xml:"priority"`
		} `xml:"priority-rule>entry"`
	} `xml:"gateways>external>list>entry"`
}

// ParsePortalConfig decodes a portal getconfig.esp response.
func ParsePortalConfig(body []byte) (PortalConfig, error) {
	var raw portalConfigXML
	if err := xml.Unmarshal(body, &raw); err != nil {
		return PortalConfig{}, fmt.Errorf("parse portal config: %w", err)
	}
	if raw.UserAuthCookie == "" || raw.UserAuthCookie == emptyCookie {
		return PortalConfig{}, fmt.Errorf("portal config has no user auth cookie: %w", ErrAuthenticationRejected)
	}

	config := PortalConfig{
		UserAuthCookie:         raw.UserAuthCookie,
		PrelogonUserAuthCookie: raw.PrelogonUserAuthCookie,
		ConnectMethod:          raw.ConnectMethod,
		HIPReportInterval:      raw.HIPReportInterval,
	}
	for _, entry := range raw.Gateways {
		gateway := Gateway{Name: entry.Description, Address: entry.Name}
		// Some portals put the label in the name attribute and the host name in the description.
		if !strings.Contains(gateway.Address, ".") && strings.Contains(gateway.Name, ".") {
			gateway.Name, gateway.Address = gateway.Address, gateway.Name
		}
		for _, rule := range entry.PriorityRules {
			gateway.PriorityRules = append(gateway.PriorityRules, PriorityRule{Region: rule.Region, Priority: rule.Priority})
		}
		config.Gateways = append(config.Gateways, gateway)
	}
	return config, nil
}

// PortalGetConfig authenticates to the portal and returns its configuration with the raw response.
func (client *Client) PortalGetConfig(ctx context.Context, credential Credential) (PortalConfig, []byte, error) {
	form := client.Identity.formValues()
	form.Set("user", credential.Username)
	form.Set("passwd", samlPassword)
	form.Set("prelogin-cookie", "")
	form.Set("portal-userauthcookie", orEmptyCookie(credential.UserAuthCookie))
	form.Set("portal-prelogonuserauthcookie", orEmptyCookie(credential.PrelogonUserAuthCookie))
	form.Set("token", credential.Token)
	form.Set("inputStr", "")
	form.Set("ok", "Login")
	form.Set("serialno", client.Identity.SerialNumber)
	form.Set("csc-digest", "")
	form.Set("config-digest", "")
	form.Set("csc-support", "no")
	form.Set("host", client.Server)
	form.Set("swg-auth-token", "0")
	form.Set("swg-nonce", "0")

	body, err := client.post(ctx, "/global-protect/getconfig.esp", form)
	if err != nil {
		return PortalConfig{}, nil, err
	}
	config, err := ParsePortalConfig(body)
	return config, body, err
}
