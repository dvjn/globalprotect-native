package hip

import (
	"strings"
	"testing"
	"time"
)

func TestBuild(t *testing.T) {
	report, err := Build(Input{
		MD5:           "0123456789abcdef0123456789abcdef",
		Username:      "alice@example.com",
		HostDomain:    "example.com",
		Computer:      "laptop",
		HostID:        "host-id",
		ClientIP:      "172.30.40.108",
		ClientVersion: "6.2.8-1057",
		OS:            "Linux Fedora 44",
		Products: []Product{
			{Category: "anti-malware", Vendor: "CrowdStrike, Inc.", Name: "Crowdstrike Falcon", Version: "7.40", State: "yes"},
			{Category: "firewall", Vendor: "IPTables", Name: "IPTables", Version: "1.8.11", State: "no"},
			{Category: "patch-management", Vendor: "GNU", Name: "Flatpak", Version: "1.18.1", State: "n/a"},
			{Category: "disk-encryption", Vendor: "GitLab Inc.", Name: "cryptsetup", Version: "2.8.7", State: "n/a"},
		},
		Facts: Facts{
			Drives:     []Drive{{Name: "/", Encrypted: false}, {Name: "/home/alice", Encrypted: true}},
			Interfaces: []Interface{{Name: "wlp0s20f3", MAC: "b6:27:7a:bc:58:c0", IPv4: []string{"192.168.1.113"}}},
		},
		Now: time.Date(2026, 10, 15, 1, 2, 3, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}

	text := string(report)
	for _, want := range []string{
		"<hip-report>",
		`<md5-sum>0123456789abcdef0123456789abcdef</md5-sum>`,
		`<user-name>alice%40example.com</user-name>`,
		`<generate-time>10/15/2026 01:02:03</generate-time>`,
		`<hip-report-version>4</hip-report-version>`,
		`<entry name="host-info">`,
		`<client-version>6.2.8-1057</client-version>`,
		`<os>Linux Fedora 44</os>`,
		`<domain>example.com</domain>`,
		`<mac-address>b6:27:7a:bc:58:c0</mac-address>`,
		`<entry name="192.168.1.113"></entry>`,
		`<Prod vendor="CrowdStrike, Inc." name="Crowdstrike Falcon" version="7.40" prodType="3" osType="1"></Prod>`,
		`<real-time-protection>yes</real-time-protection>`,
		`<is-enabled>no</is-enabled>`,
		`<is-enabled>n/a</is-enabled>`,
		"<drive-name>/</drive-name>\n                <enc-state>unencrypted</enc-state>",
		"<drive-name>/home/alice</drive-name>\n                <enc-state>encrypted</enc-state>",
		"<drive-name>All</drive-name>\n                <enc-state>unencrypted</enc-state>",
		`<entry name="data-loss-prevention">`,
		`<missing-patches></missing-patches>`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %s\n%s", want, text)
		}
	}
}

func TestBuildPutsProductsInTheirCategory(t *testing.T) {
	report, err := Build(Input{Products: []Product{{Category: "firewall", Vendor: "Red Hat, Inc.", Name: "Firewalld", State: "yes"}}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(report)
	firewall := strings.Index(text, `<entry name="firewall">`)
	product := strings.Index(text, `name="Firewalld"`)
	patches := strings.Index(text, `<entry name="patch-management">`)
	if !(firewall < product && product < patches) {
		t.Errorf("Firewalld is not inside the firewall category:\n%s", text)
	}
}
