package internal_test

import (
	"os/exec"
	"slices"
	"strings"
	"testing"
)

const module = "github.com/dvjn/globalprotect-native/"

// portable packages build for any OS: an Android or macOS app links them, and supplies its own
// engine.Platform. mobile is the Android app's.
var portable = []string{
	"internal/config",
	"internal/control",
	"internal/engine",
	"internal/gp",
	"internal/hip",
	"internal/profile",
	"internal/split",
	"internal/state",
	"internal/tunnel",
	"mobile",
}

// platformOnly are what portable packages may not depend on, even indirectly.
var platformOnly = []string{
	"os/exec",
	"golang.org/x/sys/unix",
	"github.com/vishvananda/netlink",
	"github.com/godbus/dbus/v5",
	"fyne.io/systray",
	module + "internal/platform/",
}

func TestPortablePackagesStayPortable(t *testing.T) {
	for _, pkg := range portable {
		output, err := exec.Command("go", "list", "-deps", module+pkg).Output()
		if err != nil {
			t.Fatalf("go list %s: %v", pkg, err)
		}
		for dependency := range strings.FieldsSeq(string(output)) {
			for _, forbidden := range platformOnly {
				if dependency == forbidden || strings.HasSuffix(forbidden, "/") && strings.HasPrefix(dependency, forbidden) {
					t.Errorf("%s depends on %s", pkg, dependency)
				}
			}
		}
	}
}

// TestImporters keeps the Linux platform behind the daemon and the root commands, and the
// desktop session talking to the daemon only through the control socket.
func TestImporters(t *testing.T) {
	allowed := map[string][]string{
		"internal/platform/linux": {"cmd/gpn", "internal/daemon"},
		"internal/daemon":         {"cmd/gpn"},
		"internal/engine":         {"cmd/gpn", "internal/daemon", "internal/platform/linux", "internal/profile", "mobile"},
	}
	output, err := exec.Command("go", "list", "-f", `{{.ImportPath}} {{join .Imports " "}}`, module+"...").Output()
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(output)) {
		fields := strings.Fields(line)
		importer := strings.TrimPrefix(fields[0], module)
		for _, imported := range fields[1:] {
			if strings.HasPrefix(imported, module+"internal/platform/linux/") && !strings.HasPrefix(importer, "internal/platform/linux") {
				t.Errorf("%s imports %s, which only the Linux platform may use", importer, imported)
			}
			allowedImporters, guarded := allowed[strings.TrimPrefix(imported, module)]
			if guarded && !slices.Contains(allowedImporters, importer) {
				t.Errorf("%s imports %s", importer, imported)
			}
		}
	}
}
