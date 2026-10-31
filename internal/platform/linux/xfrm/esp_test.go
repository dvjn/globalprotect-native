package xfrm

import (
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/dvjn/globalprotect-native/internal/gp"
)

func TestSetAlgorithms(t *testing.T) {
	keys := gp.ESPKeys{EncryptionKey: make([]byte, 36), IntegrityKey: make([]byte, 20)}

	var gcm netlink.XfrmState
	if err := setAlgorithms(&gcm, gp.ESPConfig{Encryption: "aes-256-gcm", Integrity: "sha1"}, keys); err != nil {
		t.Fatal(err)
	}
	if gcm.Aead == nil || gcm.Aead.Name != "rfc4106(gcm(aes))" || gcm.Aead.ICVLen != 128 || gcm.Auth != nil {
		t.Errorf("GCM: got aead %+v, auth %+v", gcm.Aead, gcm.Auth)
	}

	var cbc netlink.XfrmState
	if err := setAlgorithms(&cbc, gp.ESPConfig{Encryption: "aes-128-cbc", Integrity: "sha1"}, keys); err != nil {
		t.Fatal(err)
	}
	if cbc.Crypt == nil || cbc.Crypt.Name != "cbc(aes)" || cbc.Auth == nil || cbc.Auth.TruncateLen != 96 {
		t.Errorf("CBC: got crypt %+v, auth %+v", cbc.Crypt, cbc.Auth)
	}

	if err := setAlgorithms(&netlink.XfrmState{}, gp.ESPConfig{Encryption: "des"}, keys); err == nil {
		t.Error("accepted an unsupported cipher")
	}
}
