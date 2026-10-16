package gp

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

const loginResponse = `<?xml version='1.0' encoding='utf-8'?>
<jnlp>
  <application-desc>
    <argument>(null)</argument>
    <argument>0123456789abcdef0123456789abcdef</argument>
    <argument>persistent</argument>
    <argument>GW-India-North</argument>
    <argument>alice@example.com</argument>
    <argument>cas</argument>
    <argument>vsys1</argument>
    <argument>%28empty_domain%29</argument>
    <argument>(null)</argument>
    <argument/>
    <argument/>
    <argument/>
    <argument>tunnel</argument>
    <argument>-1</argument>
    <argument>4100</argument>
    <argument>172.30.46.188</argument>
  </application-desc>
</jnlp>`

func TestParseGatewayLogin(t *testing.T) {
	session, err := ParseGatewayLogin([]byte(loginResponse), "laptop")
	if err != nil {
		t.Fatal(err)
	}
	want := Session{
		Username:    "alice@example.com",
		AuthCookie:  "0123456789abcdef0123456789abcdef",
		Portal:      "GW-India-North",
		Domain:      "(empty_domain)",
		PreferredIP: "172.30.46.188",
		Computer:    "laptop",
	}
	if session != want {
		t.Errorf("got %+v, want %+v", session, want)
	}
}

func TestParseGatewayLoginError(t *testing.T) {
	body := `<response status="error"><error>Assign private IP address failed</error></response>`
	_, err := ParseGatewayLogin([]byte(body), "laptop")
	if err == nil || !strings.Contains(err.Error(), "Assign private IP address failed") {
		t.Errorf("err = %v, want one with the gateway error", err)
	}
}

const gatewayConfigResponse = `<?xml version="1.0" encoding="UTF-8" ?>
<response status="success">
  <need-tunnel>yes</need-tunnel>
  <ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url>
  <lifetime>2592000</lifetime>
  <timeout>10800</timeout>
  <gw-address>0.0.0.0</gw-address>
  <connected-gw-ip>203.0.113.10</connected-gw-ip>
  <quarantine>no</quarantine>
  <no-direct-access-to-local-network>no</no-direct-access-to-local-network>
  <ip-address>172.30.46.188</ip-address>
  <netmask>255.255.255.255</netmask>
  <ip-address-v6>fd00::5</ip-address-v6>
  <mtu>1280</mtu>
  <hip-report-interval>3600</hip-report-interval>
  <dns><member>172.30.41.1</member></dns>
  <dns-suffix><member>corp.example.com</member></dns-suffix>
  <include-split-tunneling-domain><member>*.corp.example.com</member></include-split-tunneling-domain>
  <access-routes><member>0.0.0.0/0</member><member>172.30.41.1/32</member></access-routes>
  <exclude-access-routes><member>192.168.1.0/27</member></exclude-access-routes>
  <exclude-split-tunneling-domain><member>*.linkedin.com</member><member>fast.com</member></exclude-split-tunneling-domain>
  <ipsec>
    <udp-port>4501</udp-port>
    <ipsec-mode>esp-tunnel</ipsec-mode>
    <enc-algo>aes-256-gcm</enc-algo>
    <hmac-algo>sha1</hmac-algo>
    <c2s-spi>0xDEADBEEF</c2s-spi>
    <s2c-spi>0x0000BACC</s2c-spi>
    <ekey-c2s><bits>256</bits><val>000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f</val></ekey-c2s>
    <akey-c2s><bits>160</bits><val>000102030405060708090a0b0c0d0e0f10111213</val></akey-c2s>
    <ekey-s2c><bits>256</bits><val>1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100</val></ekey-s2c>
    <akey-s2c><bits>160</bits><val>131211100f0e0d0c0b0a09080706050403020100</val></akey-s2c>
  </ipsec>
</response>`

func TestParseGatewayConfig(t *testing.T) {
	config, err := ParseGatewayConfig([]byte(gatewayConfigResponse))
	if err != nil {
		t.Fatal(err)
	}

	if config.ClientIP != "172.30.46.188" || config.GatewayAddress != "203.0.113.10" || config.Quarantined ||
		!config.LocalNetworkAccess || config.SSLTunnelPath != "/ssl-tunnel-connect.sslvpn" {
		t.Errorf("addresses: got %+v", config)
	}
	if config.Netmask != "255.255.255.255" || config.ClientIPv6 != "fd00::5" || config.MTU != 1280 {
		t.Errorf("addressing: got netmask %q, IPv6 %q, MTU %d", config.Netmask, config.ClientIPv6, config.MTU)
	}
	if config.LifetimeSeconds != 2592000 || config.IdleTimeout != 10800 || config.HIPReportInterval != 3600 {
		t.Errorf("timeouts: got %d, %d, %d", config.LifetimeSeconds, config.IdleTimeout, config.HIPReportInterval)
	}
	lists := map[string][2][]string{
		"DNS servers":     {config.DNSServers, {"172.30.41.1"}},
		"DNS suffixes":    {config.DNSSuffixes, {"corp.example.com"}},
		"include routes":  {config.IncludeRoutes, {"0.0.0.0/0", "172.30.41.1/32"}},
		"exclude routes":  {config.ExcludeRoutes, {"192.168.1.0/27"}},
		"include domains": {config.IncludeDomains, {"*.corp.example.com"}},
		"exclude domains": {config.ExcludeDomains, {"*.linkedin.com", "fast.com"}},
	}
	for name, pair := range lists {
		if !reflect.DeepEqual(pair[0], pair[1]) {
			t.Errorf("%s = %v, want %v", name, pair[0], pair[1])
		}
	}
	quarantined := strings.Replace(gatewayConfigResponse, "<quarantine>no</quarantine>", "<quarantine>yes</quarantine>", 1)
	if config, err := ParseGatewayConfig([]byte(quarantined)); err != nil || !config.Quarantined {
		t.Errorf("quarantine yes: Quarantined = %t, err = %v", config.Quarantined, err)
	}

	esp := config.ESP
	if esp == nil {
		t.Fatal("ESP config missing")
	}
	if esp.UDPPort != 4501 || esp.Encryption != "aes-256-gcm" || esp.Integrity != "sha1" {
		t.Errorf("ESP: got %+v", esp)
	}
	if esp.ClientToServer.SPI != 0xDEADBEEF || esp.ServerToClient.SPI != 0xBACC {
		t.Errorf("SPIs: got %#x, %#x", esp.ClientToServer.SPI, esp.ServerToClient.SPI)
	}
	if len(esp.ClientToServer.EncryptionKey) != 32 || len(esp.ServerToClient.IntegrityKey) != 20 {
		t.Errorf("key lengths: got %d, %d", len(esp.ClientToServer.EncryptionKey), len(esp.ServerToClient.IntegrityKey))
	}
	if esp.ServerToClient.EncryptionKey[0] != 0x1f {
		t.Errorf("server-to-client key starts with %#x, want 0x1f", esp.ServerToClient.EncryptionKey[0])
	}
}

func TestParseGatewayConfigRejectsWrongKeyLength(t *testing.T) {
	body := strings.Replace(gatewayConfigResponse, "<bits>160</bits><val>000102", "<bits>128</bits><val>000102", 1)
	if _, err := ParseGatewayConfig([]byte(body)); err == nil {
		t.Error("succeeded with a key shorter than its bit count says, want error")
	}
}

func TestRedactGatewayConfig(t *testing.T) {
	redacted := Redact([]byte(gatewayConfigResponse))
	for _, secret := range []string{"DEADBEEF", "0x0000BACC", "000102030405", "1f1e1d1c"} {
		if bytes.Contains(redacted, []byte(secret)) {
			t.Errorf("Redact left %q in the gateway config", secret)
		}
	}
	for _, kept := range []string{"<lifetime>2592000</lifetime>", "*.linkedin.com", "<bits>256</bits>"} {
		if !bytes.Contains(redacted, []byte(kept)) {
			t.Errorf("Redact removed %q", kept)
		}
	}
}
