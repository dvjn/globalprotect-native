package mobile

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/control"
	"github.com/dvjn/globalprotect-native/internal/engine"
	"github.com/dvjn/globalprotect-native/internal/gp"
)

type fakeApp struct {
	lock      sync.Mutex
	protected []int
	refuse    bool
	inventory string
}

func (app *fakeApp) Protect(fd int) bool {
	app.lock.Lock()
	defer app.lock.Unlock()
	app.protected = append(app.protected, fd)
	return !app.refuse
}

func (app *fakeApp) Establish(*TunnelConfig) (int, error) { return -1, errors.New("no VPN in tests") }
func (app *fakeApp) DNSServer() string                    { return "" }
func (app *fakeApp) HIPInventory() string                 { return app.inventory }
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

func TestHIPInventory(t *testing.T) {
	app := &fakeApp{inventory: `{"products": [{"category": "anti-malware", "vendor": "V", "name": "N", "version": "1", "state": "yes"}],
		"drives": [{"name": "/data", "encrypted": true}], "interfaces": [{"name": "wlan0", "mac": "02:00:00:00:00:01", "ipv4": ["192.168.1.5"]}]}`}
	products, facts := newPlatform(app).HIPInventory()
	if len(products) != 1 || products[0].State != "yes" || len(facts.Drives) != 1 || !facts.Drives[0].Encrypted ||
		len(facts.Interfaces) != 1 || facts.Interfaces[0].IPv4[0] != "192.168.1.5" {
		t.Errorf("got %+v, %+v", products, facts)
	}
	if products, facts := newPlatform(&fakeApp{}).HIPInventory(); products != nil || facts.Drives != nil {
		t.Errorf("an empty inventory gave %+v, %+v", products, facts)
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
