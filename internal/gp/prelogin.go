package gp

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	"time"
)

// Prelogin is the portal's answer to prelogin.esp: how the user must authenticate.
type Prelogin struct {
	Status             string `xml:"status"`
	Message            string `xml:"msg"`
	CASAuth            string `xml:"cas-auth"`
	SAMLMethod         string `xml:"saml-auth-method"`
	SAMLRequest        string `xml:"saml-request"`
	SAMLDefaultBrowser string `xml:"saml-default-browser"`
	SAMLRequestTimeout int    `xml:"saml-request-timeout"`
	Region             string `xml:"region"`
	TenantID           string `xml:"tenant-id"`
}

// UsesCAS reports whether the portal authenticates through Prisma Access Cloud Authentication.
func (prelogin Prelogin) UsesCAS() bool {
	return prelogin.CASAuth == "yes"
}

// LoginPage returns the HTML page that starts SAML login in a browser.
func (prelogin Prelogin) LoginPage() ([]byte, error) {
	if prelogin.SAMLMethod != "POST" {
		return nil, fmt.Errorf("unsupported SAML method %q", prelogin.SAMLMethod)
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(prelogin.SAMLRequest))
}

// LoginTimeout is how long the portal waits for the SAML login to finish.
func (prelogin Prelogin) LoginTimeout() time.Duration {
	if prelogin.SAMLRequestTimeout <= 0 {
		return 10 * time.Minute
	}
	return time.Duration(prelogin.SAMLRequestTimeout) * time.Second
}

// ParsePrelogin decodes a prelogin.esp response.
func ParsePrelogin(body []byte) (Prelogin, error) {
	var prelogin Prelogin
	if err := xml.Unmarshal(body, &prelogin); err != nil {
		return Prelogin{}, fmt.Errorf("parse prelogin response: %w", err)
	}
	if !strings.EqualFold(prelogin.Status, "success") {
		return Prelogin{}, fmt.Errorf("prelogin failed: %s", prelogin.Message)
	}
	return prelogin, nil
}

// PortalPrelogin asks the portal how to authenticate, announcing support for CAS in the default browser.
func (client *Client) PortalPrelogin(ctx context.Context) (Prelogin, error) {
	form := client.Identity.formValues()
	form.Set("tmp", "tmp")
	form.Set("default-browser", "4")
	form.Set("cas-support", "yes")

	body, err := client.post(ctx, "/global-protect/prelogin.esp", form)
	if err != nil {
		return Prelogin{}, err
	}
	return ParsePrelogin(body)
}
