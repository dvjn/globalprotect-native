package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dvjn/globalprotect-native/internal/control"
	"github.com/dvjn/globalprotect-native/internal/update"
)

const (
	// updateDelay is how long after starting the daemon first looks for a release while
	// check_updates is on, and updateInterval how often it looks again.
	updateDelay    = 5 * time.Minute
	updateInterval = 6 * time.Hour
	// updateTimeout bounds checking for and downloading one release.
	updateTimeout = 10 * time.Minute
	// updateCache is the daemon's CacheDirectory, where the package waits for its installer.
	updateCache = "/var/cache/globalprotect-native"
	// reconnectAfterUpdate is how long the reconnect marker holds, should the daemon not
	// start again soon after an update stopped it.
	reconnectAfterUpdate = 15 * time.Minute
)

// watchUpdates looks for a release now and then until ctx ends, while check_updates is on, and
// tells clients about a newer one; installing it is up to the user. It reads the settings each
// time, so switching check_updates needs no restart.
func (server *daemon) watchUpdates(ctx context.Context) {
	timer := time.NewTimer(updateDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if profile, err := server.loadProfile(); err == nil && profile.Settings.CheckUpdates {
			if _, release, newer, err := server.latestRelease(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "Could not look for an update:", err)
			} else {
				server.changeReleases(func(releases *control.Update) { releases.Available = availableVersion(release, newer) })
			}
		} else {
			server.changeReleases(func(releases *control.Update) { releases.Available = "" })
		}
		timer.Reset(updateInterval)
	}
}

// prepareUpdate downloads the latest release if it is newer than this daemon. It returns what
// to tell the user and, when there is a release to install, the install to run once they have
// been told: the installer restarts the daemon, which could otherwise end before answering.
func (server *daemon) prepareUpdate() (string, func(), error) {
	if !update.IsRelease(server.currentVersion()) {
		return "", nil, fmt.Errorf("gpn %s is a development build and cannot update itself", server.version)
	}
	if !server.updating.TryLock() {
		return "", nil, errUpdating
	}
	defer server.updating.Unlock()
	server.lock.Lock()
	installing := server.releases.Installing
	server.lock.Unlock()
	if installing {
		return "", nil, errUpdating
	}

	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	manager, release, newer, err := server.latestRelease(ctx)
	if err != nil {
		return "", nil, err
	}
	current := server.currentVersion()
	// One change, so the agent never sees the release as merely available and offers it.
	server.changeReleases(func(releases *control.Update) {
		releases.Available, releases.Installing, releases.Error = availableVersion(release, newer), newer, ""
	})
	if !newer {
		return fmt.Sprintf("Up to date: %s is the latest release.", current), nil, nil
	}

	fmt.Fprintf(os.Stderr, "Updating from %s to %s with %s.\n", current, release.Version, manager.Name)
	path, err := update.Download(ctx, release, updateCache)
	if err != nil {
		server.changeReleases(func(releases *control.Update) { releases.Installing = false })
		return "", nil, err
	}
	install := func() {
		err := update.Install(manager, path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Update failed:", err)
		}
		server.changeReleases(func(releases *control.Update) {
			releases.Installing = false
			if err != nil {
				releases.Error = err.Error()
			}
		})
	}
	return fmt.Sprintf("Installing %s with %s; the daemon restarts when it is done.", release.Version, manager.Name), install, nil
}

var errUpdating = errors.New("an update is already in progress")

// latestRelease finds the latest release for the package manager that installed gpn, and
// whether it is newer than this daemon.
func (server *daemon) latestRelease(ctx context.Context) (*update.Manager, update.Release, bool, error) {
	binary, err := os.Executable()
	if err != nil {
		return nil, update.Release{}, false, err
	}
	manager, err := update.Detect(binary)
	if err != nil {
		return nil, update.Release{}, false, err
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()
	release, err := update.Latest(ctx, manager)
	if err != nil {
		return nil, update.Release{}, false, err
	}
	return manager, release, update.Newer(release.Version, server.currentVersion()), nil
}

// availableVersion is what the status offers: the release's version when it is newer.
func availableVersion(release update.Release, newer bool) string {
	if newer {
		return release.Version
	}
	return ""
}

// currentVersion is this build's release version, without the commit that mise appends.
func (server *daemon) currentVersion() string {
	current, _, _ := strings.Cut(server.version, "-")
	return current
}

// reconnectMarker holds, while an update restarts the daemon, the home directory of the user
// whose tunnel was up, so the new daemon brings that tunnel back.
func reconnectMarker(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "reconnect-after-update")
}

// rememberTunnel writes the reconnect marker when the daemon stops during an update with a
// tunnel up. It runs on the way out, so a tunnel the user ended meanwhile stays down.
func (server *daemon) rememberTunnel() {
	server.lock.Lock()
	remember := server.releases.Installing && server.stop != nil
	userHome := server.userHome
	server.lock.Unlock()
	if !remember {
		return
	}
	profile, err := server.loadProfile()
	if err == nil {
		err = os.WriteFile(reconnectMarker(profile.StatePath), []byte(userHome), 0o600)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "The tunnel will not come back after the update:", err)
	}
}

// takeReconnectMarker removes the marker and returns the home directory it holds, if a recent
// update left it.
func takeReconnectMarker(statePath string) (string, bool) {
	marker := reconnectMarker(statePath)
	info, err := os.Stat(marker)
	if err != nil {
		return "", false
	}
	userHome, err := os.ReadFile(marker)
	os.Remove(marker)
	return string(userHome), err == nil && time.Since(info.ModTime()) < reconnectAfterUpdate
}
