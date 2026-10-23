// Package dns points the system resolver at the tunnel's DNS servers.
// It uses systemd-resolved when it runs, and rewrites /etc/resolv.conf otherwise.
package dns

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	resolvConf       = "/etc/resolv.conf"
	resolvedSocket   = "/run/systemd/resolve/io.systemd.Resolve"
	backupDirectory  = "/run/globalprotect-native"
	resolvConfBackup = backupDirectory + "/resolv.conf"
	// resolvConfLink holds the symlink target when resolv.conf was a symlink.
	resolvConfLink = backupDirectory + "/resolv.conf.symlink"
	writtenMarker  = "# Written by gpn while the tunnel is up; restored on disconnect.\n"
)

// Settings is what the gateway asks the resolver to use.
type Settings struct {
	Device   string
	Servers  []string
	Suffixes []string
	// Selective limits the servers to RoutingDomains, such as "~example.com", and the
	// suffixes; other names go to the usual servers. Only systemd-resolved can do that: with
	// /etc/resolv.conf every name goes to the servers.
	Selective      bool
	RoutingDomains []string
}

// Restore undoes Apply.
type Restore func() error

// Apply configures the resolver and returns how to undo it.
func Apply(settings Settings) (Restore, error) {
	if len(settings.Servers) == 0 {
		return func() error { return nil }, nil
	}
	if usesResolved() {
		return applyResolved(settings)
	}
	return applyResolvConf(settings)
}

func usesResolved() bool {
	_, err := os.Stat(resolvedSocket)
	return err == nil
}

// applyResolved routes every query to the tunnel's servers with the "~." routing domain, or,
// when selective, only the queries of the routing domains and suffixes.
// resolved forgets the link's settings by itself when the device disappears.
func applyResolved(settings Settings) (Restore, error) {
	domains, defaultRoute := []string{"~."}, "yes"
	if settings.Selective {
		domains, defaultRoute = settings.RoutingDomains, "no"
	}
	domains = append(domains, settings.Suffixes...)
	for _, command := range [][]string{
		append([]string{"dns", settings.Device}, settings.Servers...),
		append([]string{"domain", settings.Device}, domains...),
		{"default-route", settings.Device, defaultRoute},
	} {
		if output, err := exec.Command("resolvectl", command...).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("resolvectl %s: %w: %s", strings.Join(command, " "), err, output)
		}
	}
	return func() error {
		return exec.Command("resolvectl", "revert", settings.Device).Run()
	}, nil
}

// applyResolvConf replaces /etc/resolv.conf, keeping the original in /run/globalprotect-native.
func applyResolvConf(settings Settings) (Restore, error) {
	if err := RestoreLeftovers(); err != nil {
		return nil, err
	}
	if err := backUpResolvConf(); err != nil {
		return nil, err
	}

	var written strings.Builder
	written.WriteString(writtenMarker)
	for _, server := range settings.Servers {
		fmt.Fprintf(&written, "nameserver %s\n", server)
	}
	if len(settings.Suffixes) > 0 {
		fmt.Fprintf(&written, "search %s\n", strings.Join(settings.Suffixes, " "))
	}
	if err := replaceFile(resolvConf, []byte(written.String())); err != nil {
		return nil, err
	}
	return RestoreLeftovers, nil
}

// backUpResolvConf saves resolv.conf's content, and its target too when it is a symlink.
func backUpResolvConf() error {
	if err := os.MkdirAll(backupDirectory, 0o700); err != nil {
		return err
	}
	if target, err := os.Readlink(resolvConf); err == nil {
		if err := os.WriteFile(resolvConfLink, []byte(target), 0o600); err != nil {
			return err
		}
	}
	original, err := os.ReadFile(resolvConf)
	if err != nil {
		return err
	}
	return os.WriteFile(resolvConfBackup, original, 0o644)
}

// RestoreLeftovers puts back a resolv.conf that an earlier run, maybe one that crashed, replaced.
func RestoreLeftovers() error {
	original, err := os.ReadFile(resolvConfBackup)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	if target, err := os.ReadFile(resolvConfLink); err == nil {
		if err := replaceWithSymlink(resolvConf, string(target)); err != nil {
			return err
		}
		os.Remove(resolvConfLink)
	} else if err := replaceFile(resolvConf, original); err != nil {
		return err
	}
	return os.Remove(resolvConfBackup)
}

func replaceWithSymlink(path, target string) error {
	temporary := filepath.Join(filepath.Dir(path), ".gpn-"+filepath.Base(path))
	os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// replaceFile writes a new file and renames it over path, so readers never see half a file.
func replaceFile(path string, content []byte) error {
	temporary := filepath.Join(filepath.Dir(path), ".gpn-"+filepath.Base(path))
	if err := os.WriteFile(temporary, content, 0o644); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
