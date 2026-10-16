package gp

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParsePreloginCAS(t *testing.T) {
	page := `<html><form method="POST" action="https://cloud-auth.example/auth"></form></html>`
	body := `<?xml version="1.0" encoding="UTF-8" ?>
<prelogin-response>
<status>Success</status>
<msg></msg>
<saml-default-browser>yes</saml-default-browser>
<tenant-id>42</tenant-id><cas-auth>yes</cas-auth>
<saml-auth-method>POST</saml-auth-method>
<saml-request-timeout>600</saml-request-timeout>
<saml-request>` + base64.StdEncoding.EncodeToString([]byte(page)) + `</saml-request>
</prelogin-response>`

	prelogin, err := ParsePrelogin([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !prelogin.UsesCAS() {
		t.Error("UsesCAS() = false, want true")
	}
	if prelogin.TenantID != "42" {
		t.Errorf("TenantID = %q, want 42", prelogin.TenantID)
	}
	if prelogin.LoginTimeout() != 10*time.Minute {
		t.Errorf("LoginTimeout() = %v, want 10m", prelogin.LoginTimeout())
	}
	decoded, err := prelogin.LoginPage()
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != page {
		t.Errorf("LoginPage() = %q, want %q", decoded, page)
	}
}

func TestParsePreloginError(t *testing.T) {
	body := `<prelogin-response><status>Error</status><msg>Invalid client</msg></prelogin-response>`
	_, err := ParsePrelogin([]byte(body))
	if err == nil || !strings.Contains(err.Error(), "Invalid client") {
		t.Errorf("err = %v, want one mentioning the portal message", err)
	}
}

func TestParseCallback(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{"plain", "globalprotectcallback:cas-as=1&un=alice@example.com&token=abc.def.ghi"},
		{"leading slashes", "globalprotectcallback://cas-as=1&un=alice@example.com&token=abc.def.ghi"},
		{"escaped", "globalprotectcallback:cas-as%3D1%26un%3Dalice%40example.com%26token%3Dabc.def.ghi"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			callback, err := ParseCallback(test.uri)
			if err != nil {
				t.Fatal(err)
			}
			if callback.Username != "alice@example.com" || callback.Token != "abc.def.ghi" {
				t.Errorf("got %+v", callback)
			}
		})
	}
}

func TestParseCallbackRejects(t *testing.T) {
	for _, uri := range []string{
		"https://example.com",
		"globalprotectcallback:PGh0bWw+",
		"globalprotectcallback:cas-as=1&un=alice@example.com",
	} {
		if _, err := ParseCallback(uri); err == nil {
			t.Errorf("ParseCallback(%q) succeeded, want error", uri)
		}
	}
}

func TestParsePortalConfig(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8" ?>
<policy>
  <portal-userauthcookie>user-cookie</portal-userauthcookie>
  <portal-prelogonuserauthcookie>empty</portal-prelogonuserauthcookie>
  <connect-method>user-logon</connect-method>
  <hip-collection><hip-report-interval>3600</hip-report-interval></hip-collection>
  <gateways>
    <external>
      <list>
        <entry name="in.gw.example.com">
          <description>india-west</description>
          <priority-rule>
            <entry name="IN"><priority>1</priority></entry>
            <entry name="Any"><priority>0</priority></entry>
          </priority-rule>
        </entry>
        <entry name="eu-central">
          <description>eu.gw.example.com</description>
        </entry>
      </list>
    </external>
  </gateways>
</policy>`

	config, err := ParsePortalConfig([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if config.UserAuthCookie != "user-cookie" || config.ConnectMethod != "user-logon" || config.HIPReportInterval != 3600 {
		t.Errorf("got %+v", config)
	}
	want := []Gateway{
		{Name: "india-west", Address: "in.gw.example.com", PriorityRules: []PriorityRule{{"IN", 1}, {"Any", 0}}},
		{Name: "eu-central", Address: "eu.gw.example.com"},
	}
	if !reflect.DeepEqual(config.Gateways, want) {
		t.Errorf("Gateways = %+v, want %+v", config.Gateways, want)
	}
}

func TestParsePortalConfigWithoutCookie(t *testing.T) {
	body := `<policy><portal-userauthcookie>empty</portal-userauthcookie></policy>`
	if _, err := ParsePortalConfig([]byte(body)); !errors.Is(err, ErrAuthenticationRejected) {
		t.Errorf("err = %v, want ErrAuthenticationRejected", err)
	}
}

func TestRedact(t *testing.T) {
	body := `<policy><portal-userauthcookie>secret1</portal-userauthcookie><auth-token>secret2</auth-token><host-id>secret3</host-id><passcode-hash>secret4</passcode-hash><connect-method>user-logon</connect-method><empty-cookie></empty-cookie></policy>`
	got := string(Redact([]byte(body)))
	for _, secret := range []string{"secret1", "secret2", "secret3", "secret4"} {
		if strings.Contains(got, secret) {
			t.Errorf("Redact left %q in %s", secret, got)
		}
	}
	if !strings.Contains(got, "<connect-method>user-logon</connect-method>") {
		t.Errorf("Redact changed a non-secret element: %s", got)
	}
}
