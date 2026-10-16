package gp

import (
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
)

// GatewayConfig is the tunnel configuration from gateway getconfig.esp.
type GatewayConfig struct {
	GatewayAddress string
	Quarantined    bool
	// LocalNetworkAccess is false when the gateway forbids reaching the local network directly.
	LocalNetworkAccess bool
	ClientIP           string
	Netmask            string
	ClientIPv6         string
	MTU                int
	DNSServers         []string
	DNSSuffixes        []string
	IncludeRoutes      []string
	ExcludeRoutes      []string
	IncludeDomains     []string
	ExcludeDomains     []string
	LifetimeSeconds    int
	IdleTimeout        int
	SSLTunnelPath      string
	HIPReportInterval  int
	ESP                *ESPConfig
}

// ESPConfig holds the IPsec parameters for the ESP-in-UDP tunnel.
type ESPConfig struct {
	UDPPort        int
	Mode           string
	Encryption     string
	Integrity      string
	ClientToServer ESPKeys
	ServerToClient ESPKeys
}

// ESPKeys is one direction of the ESP tunnel.
type ESPKeys struct {
	SPI           uint32
	EncryptionKey []byte
	IntegrityKey  []byte
}

type members struct {
	Members []string `xml:"member"`
}

type keyXML struct {
	Bits  int    `xml:"bits"`
	Value string `xml:"val"`
}

type gatewayConfigXML struct {
	Status            string  `xml:"status,attr"`
	Error             string  `xml:"error"`
	GatewayAddress    string  `xml:"gw-address"`
	ConnectedGateway  string  `xml:"connected-gw-ip"`
	Quarantine        string  `xml:"quarantine"`
	NoLocalAccess     string  `xml:"no-direct-access-to-local-network"`
	ClientIP          string  `xml:"ip-address"`
	Netmask           string  `xml:"netmask"`
	ClientIPv6        string  `xml:"ip-address-v6"`
	MTU               int     `xml:"mtu"`
	DNS               members `xml:"dns"`
	DNSSuffix         members `xml:"dns-suffix"`
	AccessRoutes      members `xml:"access-routes"`
	ExcludeRoutes     members `xml:"exclude-access-routes"`
	IncludeDomains    members `xml:"include-split-tunneling-domain"`
	ExcludeDomains    members `xml:"exclude-split-tunneling-domain"`
	Lifetime          int     `xml:"lifetime"`
	Timeout           int     `xml:"timeout"`
	SSLTunnelURL      string  `xml:"ssl-tunnel-url"`
	HIPReportInterval int     `xml:"hip-report-interval"`
	IPsec             *struct {
		UDPPort    int    `xml:"udp-port"`
		Mode       string `xml:"ipsec-mode"`
		Encryption string `xml:"enc-algo"`
		Integrity  string `xml:"hmac-algo"`
		C2SSPI     string `xml:"c2s-spi"`
		S2CSPI     string `xml:"s2c-spi"`
		EKeyC2S    keyXML `xml:"ekey-c2s"`
		AKeyC2S    keyXML `xml:"akey-c2s"`
		EKeyS2C    keyXML `xml:"ekey-s2c"`
		AKeyS2C    keyXML `xml:"akey-s2c"`
	} `xml:"ipsec"`
}

// ParseGatewayConfig decodes a gateway getconfig.esp response.
func ParseGatewayConfig(body []byte) (GatewayConfig, error) {
	var raw gatewayConfigXML
	if err := xml.Unmarshal(body, &raw); err != nil {
		return GatewayConfig{}, fmt.Errorf("parse gateway config: %w", err)
	}
	if raw.Status != "success" {
		return GatewayConfig{}, fmt.Errorf("gateway config failed: %s", raw.Error)
	}

	config := GatewayConfig{
		GatewayAddress:     gatewayAddress(raw),
		Quarantined:        raw.Quarantine == "yes",
		LocalNetworkAccess: raw.NoLocalAccess != "yes",
		ClientIP:           raw.ClientIP,
		Netmask:            raw.Netmask,
		ClientIPv6:         raw.ClientIPv6,
		MTU:                raw.MTU,
		DNSServers:         raw.DNS.Members,
		DNSSuffixes:        raw.DNSSuffix.Members,
		IncludeRoutes:      raw.AccessRoutes.Members,
		ExcludeRoutes:      raw.ExcludeRoutes.Members,
		IncludeDomains:     raw.IncludeDomains.Members,
		ExcludeDomains:     raw.ExcludeDomains.Members,
		LifetimeSeconds:    raw.Lifetime,
		IdleTimeout:        raw.Timeout,
		SSLTunnelPath:      raw.SSLTunnelURL,
		HIPReportInterval:  raw.HIPReportInterval,
	}
	if config.ClientIP == "" {
		return GatewayConfig{}, fmt.Errorf("gateway config has no client IP address")
	}

	if ipsec := raw.IPsec; ipsec != nil {
		clientToServer, err := parseESPKeys(ipsec.C2SSPI, ipsec.EKeyC2S, ipsec.AKeyC2S)
		if err != nil {
			return GatewayConfig{}, fmt.Errorf("client-to-server ESP keys: %w", err)
		}
		serverToClient, err := parseESPKeys(ipsec.S2CSPI, ipsec.EKeyS2C, ipsec.AKeyS2C)
		if err != nil {
			return GatewayConfig{}, fmt.Errorf("server-to-client ESP keys: %w", err)
		}
		config.ESP = &ESPConfig{
			UDPPort:        ipsec.UDPPort,
			Mode:           ipsec.Mode,
			Encryption:     ipsec.Encryption,
			Integrity:      ipsec.Integrity,
			ClientToServer: clientToServer,
			ServerToClient: serverToClient,
		}
	}
	return config, nil
}

// gatewayAddress is the public address to send ESP to.
// Prisma Access sends 0.0.0.0 in gw-address and the real address in connected-gw-ip.
func gatewayAddress(raw gatewayConfigXML) string {
	if raw.GatewayAddress != "" && raw.GatewayAddress != "0.0.0.0" {
		return raw.GatewayAddress
	}
	return raw.ConnectedGateway
}

func parseESPKeys(spi string, encryption, integrity keyXML) (ESPKeys, error) {
	parsedSPI, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(spi), "0x"), 16, 32)
	if err != nil {
		return ESPKeys{}, fmt.Errorf("SPI %q: %w", spi, err)
	}
	encryptionKey, err := parseKey(encryption)
	if err != nil {
		return ESPKeys{}, fmt.Errorf("encryption key: %w", err)
	}
	integrityKey, err := parseKey(integrity)
	if err != nil {
		return ESPKeys{}, fmt.Errorf("integrity key: %w", err)
	}
	return ESPKeys{SPI: uint32(parsedSPI), EncryptionKey: encryptionKey, IntegrityKey: integrityKey}, nil
}

func parseKey(key keyXML) ([]byte, error) {
	if key.Value == "" {
		return nil, nil
	}
	value, err := hex.DecodeString(key.Value)
	if err != nil {
		return nil, err
	}
	if key.Bits != 0 && len(value)*8 != key.Bits {
		return nil, fmt.Errorf("key has %d bits, want %d", len(value)*8, key.Bits)
	}
	return value, nil
}
