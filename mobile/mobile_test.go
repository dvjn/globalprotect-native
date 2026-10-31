package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/control"
	"github.com/dvjn/globalprotect-native/internal/engine"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/hip"
)

type fakeApp struct {
	lock      sync.Mutex
	protected []int
	refuse    bool
	profile   string
}

func (app *fakeApp) Protect(fd int) bool {
	app.lock.Lock()
	defer app.lock.Unlock()
	app.protected = append(app.protected, fd)
	return !app.refuse
}

func (app *fakeApp) Establish(*TunnelConfig) (int, error) { return -1, errors.New("no VPN in tests") }
func (app *fakeApp) DNSServer() string                    { return "" }
func (app *fakeApp) HIPProfile() string                   { return app.profile }
func (app *fakeApp) Log(string)                           {}

func TestDialerProtectsSockets(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	app := &fakeApp{}
	connection, err := protectedDialer(app).DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if len(app.protected) != 1 || app.protected[0] < 0 {
		t.Errorf("protected %v, want one socket", app.protected)
	}

	app.refuse = true
	if _, err := protectedDialer(app).DialContext(context.Background(), "tcp", listener.Addr().String()); err == nil {
		t.Error("connected with a socket the app could not protect")
	}
}

func TestTunnelConfig(t *testing.T) {
	settings := config.Config{IncludeDomains: []string{"*.corp.example"}, IncludeRoutes: []string{"10.0.0.0/8"}}
	network, err := engine.NewNetwork(context.Background(), net.DefaultResolver, "192.0.2.1", gp.GatewayConfig{
		ClientIP:       "10.9.0.2",
		GatewayAddress: "192.0.2.1",
		DNSServers:     []string{"10.0.0.53", "10.0.0.54"},
		DNSSuffixes:    []string{"corp.example"},
	}, settings)
	if err != nil {
		t.Fatal(err)
	}
	got := *tunnelConfig(network)
	want := TunnelConfig{
		ClientIP:      "10.9.0.2",
		MTU:           1280,
		Routes:        "10.0.0.0/8,10.0.0.53/32,10.0.0.54/32",
		DNSServers:    "10.0.0.53,10.0.0.54",
		SearchDomains: "corp.example",
		IncludeOnly:   true,
		Domains:       "*.corp.example",
	}
	if got != want {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestHIPProfile(t *testing.T) {
	app := &fakeApp{profile: `{"os_vendor": "Google", "products": [{"category": "anti-malware", "vendor": "V", "name": "N", "version": "1", "state": "yes"}],
		"drives": [{"name": "/data", "encrypted": true}], "interfaces": [{"name": "wlan0", "mac": "02:00:00:00:00:01", "ipv4": ["192.168.1.5"]}]}`}
	detected := newPlatform(app).HIPProfile()
	if detected.OSVendor != "Google" || len(detected.Products) != 1 || detected.Products[0].State != "yes" ||
		len(detected.Drives) != 1 || !detected.Drives[0].Encrypted || detected.Interfaces[0].IPv4[0] != "192.168.1.5" {
		t.Errorf("got %+v", detected)
	}
	if empty := newPlatform(&fakeApp{}).HIPProfile(); empty.Products != nil || empty.Drives != nil {
		t.Errorf("an app that detects nothing gave %+v", empty)
	}
}

// A profile exported from a laptop and imported on the phone reports the laptop, and logs in
// as it.
func TestImportedHIPProfile(t *testing.T) {
	settings := `{"portal": "vpn.example.com",
		"credential": {"username": "alice@example.com"},
		"identity": {"host_id": "phone-id", "computer": "Pixel", "os_version": "Android 17", "client_version": "6.2.8-1057"},
		"hip_profile": {"os": "Linux Fedora 44", "computer": "laptop", "host_id": "laptop-id",
			"products": [{"category": "firewall", "vendor": "Red Hat, Inc.", "name": "Firewalld", "version": "2.3", "state": "yes"}]}}`
	app := &fakeApp{profile: `{"os_vendor": "Google", "drives": [{"name": "/data", "encrypted": true}]}`}

	exported, err := ExportHIPProfile(settings, app)
	if err != nil {
		t.Fatal(err)
	}
	var profile hip.Profile
	if err := json.Unmarshal([]byte(exported), &profile); err != nil {
		t.Fatal(err)
	}
	if profile.OS != "Linux Fedora 44" || profile.Computer != "laptop" || profile.HostID != "laptop-id" ||
		profile.OSVendor != "Google" || profile.HostDomain != "example.com" || profile.ClientVersion != "6.2.8-1057" ||
		len(profile.Products) != 1 || len(profile.Drives) != 1 {
		t.Errorf("exported %s", exported)
	}

	report, err := PreviewHIPReport(settings, app)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"<host-name>laptop</host-name>", "<host-id>laptop-id</host-id>", "Firewalld", "Linux Fedora 44"} {
		if !strings.Contains(report, want) {
			t.Errorf("report lacks %s:\n%s", want, report)
		}
	}
}

func TestFinalStatus(t *testing.T) {
	for err, want := range map[error]string{
		nil: control.StateDisconnected,
		fmt.Errorf("portal: %w", gp.ErrAuthenticationRejected): control.StateNeedsLogin,
		errors.New("no route"):                                 control.StateFailed,
	} {
		if got := finalStatus(err).State; got != want {
			t.Errorf("%v: got %s, want %s", err, got, want)
		}
	}
}

func TestStartRejectsBadSettings(t *testing.T) {
	for _, settings := range []string{"", "{", `{"gateway": "x"}`} {
		if _, err := Start(settings, &fakeApp{}, nil); err == nil {
			t.Errorf("started with %q", settings)
		}
	}
}
