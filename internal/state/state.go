// Package state stores the machine identity and portal cookies between runs.
package state

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// State is everything gpn remembers between runs.
type State struct {
	HostID string `json:"host_id"`
	// Portal and Gateway are what the user chose with `gpn connect --portal --gateway`.
	// The settings file overrides them; an empty Gateway means the fastest one.
	Portal  string                  `json:"portal,omitempty"`
	Gateway string                  `json:"gateway,omitempty"`
	Portals map[string]PortalCookie `json:"portals"`
}

// PortalCookie is the saved login for one portal.
type PortalCookie struct {
	Username               string    `json:"username"`
	UserAuthCookie         string    `json:"user_auth_cookie"`
	PrelogonUserAuthCookie string    `json:"prelogon_user_auth_cookie"`
	SavedAt                time.Time `json:"saved_at"`
}

// DefaultPath is where the daemon keeps its state. It holds cookies, so only root may read it.
const DefaultPath = "/var/lib/globalprotect-native/state.json"

// Load reads the state file, creating a host ID the first time.
func Load(path string) (*State, error) {
	state := &State{}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(data, state); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}

	if state.Portals == nil {
		state.Portals = map[string]PortalCookie{}
	}
	if state.HostID == "" {
		state.HostID = newHostID()
	}
	return state, nil
}

// Save writes the state file, readable only by the user.
func (state *State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func newHostID() string {
	id := make([]byte, 16)
	rand.Read(id)
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}
