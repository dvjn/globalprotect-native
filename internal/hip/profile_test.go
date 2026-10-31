package hip

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestProfileOver(t *testing.T) {
	detected := Profile{
		OS:         "Linux Arch",
		Computer:   "laptop",
		Products:   []Product{{Category: "firewall", Name: "nftables"}},
		Drives:     []Drive{{Name: "/", Encrypted: true}},
		Interfaces: []Interface{{Name: "wlan0"}},
	}
	var imported Profile
	if err := json.Unmarshal([]byte(`{"os": "Linux Fedora 44", "products": null, "drives": []}`), &imported); err != nil {
		t.Fatal(err)
	}
	got := imported.Over(detected)
	want := Profile{
		OS:         "Linux Fedora 44",
		Computer:   "laptop",
		Products:   detected.Products,
		Drives:     []Drive{},
		Interfaces: detected.Interfaces,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestProfileSurvivesJSON(t *testing.T) {
	exported := Profile{
		OS:         "Linux Fedora 44",
		OSVendor:   "Linux",
		HostID:     "host-id",
		Products:   []Product{{Category: "anti-malware", Vendor: "V", Name: "N", Version: "1", State: "yes"}},
		Drives:     []Drive{{Name: "/", Encrypted: true}},
		Interfaces: []Interface{{Name: "eth0", MAC: "02:00:00:00:00:01", IPv4: []string{"192.0.2.5"}}},
	}
	text, err := json.Marshal(exported)
	if err != nil {
		t.Fatal(err)
	}
	var imported Profile
	if err := json.Unmarshal(text, &imported); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(imported, exported) {
		t.Errorf("read back %+v from %s", imported, text)
	}
}
