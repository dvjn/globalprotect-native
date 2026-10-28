package update

import (
	"testing"
)

const sums = `0f5c5e0b1fbd5b6b0ac4e0d3f4ca0b7b1d1e4d4a5d0c9d3f6a8b2e7c1d0f9a8b  globalprotect-native-0.3.0-1-x86_64.pkg.tar.zst
1f5c5e0b1fbd5b6b0ac4e0d3f4ca0b7b1d1e4d4a5d0c9d3f6a8b2e7c1d0f9a8b  globalprotect-native-0.3.0-1.x86_64.rpm
2f5c5e0b1fbd5b6b0ac4e0d3f4ca0b7b1d1e4d4a5d0c9d3f6a8b2e7c1d0f9a8b  globalprotect-native_0.3.0-1_amd64.deb
`

func TestFindAssetPicksEachManagersPackage(t *testing.T) {
	want := map[string]string{
		"pacman": "globalprotect-native-0.3.0-1-x86_64.pkg.tar.zst",
		"rpm":    "globalprotect-native-0.3.0-1.x86_64.rpm",
		"dpkg":   "globalprotect-native_0.3.0-1_amd64.deb",
	}
	for _, manager := range managers {
		release, err := findAsset([]byte(sums), manager.asset)
		if err != nil {
			t.Fatalf("%s: %v", manager.Name, err)
		}
		if release.Name != want[manager.Name] || release.Version != "0.3.0" || len(release.sum) != 32 {
			t.Errorf("%s: got %+v", manager.Name, release)
		}
	}
}

func TestFindAssetMissing(t *testing.T) {
	if _, err := findAsset([]byte("abc  SHA256SUMS\n"), managers[0].asset); err == nil {
		t.Error("found a package in sums without one")
	}
}

func TestOwnedBy(t *testing.T) {
	for output, want := range map[string]string{
		"globalprotect-native\n":               "globalprotect-native",
		"globalprotect-native: /usr/bin/gpn\n": "globalprotect-native",
		"globalprotect-native-bin\n":           "globalprotect-native-bin",
		"":                                     "",
	} {
		if got := ownedBy([]byte(output)); got != want {
			t.Errorf("ownedBy(%q) = %q, want %q", output, got, want)
		}
	}
}

func TestNewer(t *testing.T) {
	for _, test := range []struct {
		a, b string
		want bool
	}{
		{"0.3.0", "0.2.0", true},
		{"0.10.0", "0.9.1", true},
		{"1.0", "0.9.9", true},
		{"0.2.0", "0.2.0", false},
		{"0.2.0", "0.3.0", false},
		{"0.2.0.0", "0.2.0", false},
		{"0.3.0", "dev", false},
	} {
		if got := Newer(test.a, test.b); got != test.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", test.a, test.b, got, test.want)
		}
	}
}
