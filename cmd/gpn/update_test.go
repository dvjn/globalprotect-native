package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReconnectMarker(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	if _, found := takeReconnectMarker(statePath); found {
		t.Fatal("found a marker that was never written")
	}

	os.WriteFile(reconnectMarker(statePath), []byte("/home/user"), 0o600)
	if userHome, found := takeReconnectMarker(statePath); !found || userHome != "/home/user" {
		t.Errorf("got %q, %v; want /home/user, true", userHome, found)
	}
	if _, found := takeReconnectMarker(statePath); found {
		t.Error("the marker was not removed")
	}

	os.WriteFile(reconnectMarker(statePath), nil, 0o600)
	old := time.Now().Add(-reconnectAfterUpdate - time.Minute)
	os.Chtimes(reconnectMarker(statePath), old, old)
	if _, found := takeReconnectMarker(statePath); found {
		t.Error("an expired marker reconnected")
	}
}
