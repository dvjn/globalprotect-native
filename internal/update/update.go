// Package update installs the latest GitHub release with the package manager that installed gpn.
package update

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	packageName = "globalprotect-native"
	releases    = "https://github.com/dvjn/globalprotect-native/releases"
	installUnit = "globalprotect-native-update"
)

// Manager is a package manager that gpn can update itself with.
type Manager struct {
	Name string
	// owner asks which package owns a file; the answer starts with the package's name.
	owner []string
	// asset matches the package's file name in SHA256SUMS and captures its version.
	asset *regexp.Regexp
	// install installs a package file without asking anything, keeping edited config files.
	install []string
}

var managers = []Manager{
	{
		Name:    "pacman",
		owner:   []string{"pacman", "-Qqo"},
		asset:   regexp.MustCompile(`^globalprotect-native-([0-9.]+)-[0-9]+-x86_64\.pkg\.tar\.zst$`),
		install: []string{"pacman", "-U", "--noconfirm"},
	},
	{
		Name:    "rpm",
		owner:   []string{"rpm", "-qf", "--queryformat", "%{NAME}"},
		asset:   regexp.MustCompile(`^globalprotect-native-([0-9.]+)-[0-9]+\.x86_64\.rpm$`),
		install: []string{"rpm", "-U"},
	},
	{
		Name:    "dpkg",
		owner:   []string{"dpkg-query", "-S"},
		asset:   regexp.MustCompile(`^globalprotect-native_([0-9.]+)-[0-9]+_amd64\.deb$`),
		install: []string{"dpkg", "--force-confdef", "--force-confold", "-i"},
	},
}

// Detect finds the package manager whose globalprotect-native package installed binary.
func Detect(binary string) (*Manager, error) {
	for i := range managers {
		manager := &managers[i]
		if _, err := exec.LookPath(manager.owner[0]); err != nil {
			continue
		}
		output, err := exec.Command(manager.owner[0], append(manager.owner[1:], binary)...).Output()
		if err == nil && ownedBy(output) == packageName {
			return manager, nil
		}
	}
	return nil, fmt.Errorf("%s was not installed from a %s package", binary, packageName)
}

// ownedBy is the package name in an owner query's answer: "name" from pacman and rpm,
// "name: /path" from dpkg.
func ownedBy(output []byte) string {
	fields := strings.Fields(string(output))
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimSuffix(fields[0], ":")
}

// Release is the manager's package file in the latest release.
type Release struct {
	Version string
	Name    string
	sum     []byte
}

// Latest reads SHA256SUMS of the latest release and finds the manager's package in it.
func Latest(ctx context.Context, manager *Manager) (Release, error) {
	body, err := fetch(ctx, releases+"/latest/download/SHA256SUMS")
	if err != nil {
		return Release{}, err
	}
	defer body.Close()
	sums, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return Release{}, err
	}
	return findAsset(sums, manager.asset)
}

func findAsset(sums []byte, asset *regexp.Regexp) (Release, error) {
	scanner := bufio.NewScanner(bytes.NewReader(sums))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		match := asset.FindStringSubmatch(name)
		if match == nil {
			continue
		}
		sum, err := hex.DecodeString(fields[0])
		if err != nil || len(sum) != sha256.Size {
			return Release{}, fmt.Errorf("SHA256SUMS has a malformed sum for %s", name)
		}
		return Release{Version: match[1], Name: name, sum: sum}, nil
	}
	return Release{}, errors.New("the latest release has no package for this package manager")
}

// Newer reports whether version a is later than b. Both are dotted numbers such as 0.2.0;
// anything else, such as a development build's "dev", is never newer nor older.
func Newer(a, b string) bool {
	partsA, okA := parseVersion(a)
	partsB, okB := parseVersion(b)
	if !okA || !okB {
		return false
	}
	for i := range max(len(partsA), len(partsB)) {
		var x, y int
		if i < len(partsA) {
			x = partsA[i]
		}
		if i < len(partsB) {
			y = partsB[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

// IsRelease reports whether version is a release's, which Newer can compare.
func IsRelease(version string) bool {
	_, ok := parseVersion(version)
	return ok
}

func parseVersion(version string) ([]int, bool) {
	var parts []int
	for field := range strings.SplitSeq(version, ".") {
		part, err := strconv.Atoi(field)
		if err != nil || part < 0 {
			return nil, false
		}
		parts = append(parts, part)
	}
	return parts, true
}

// Download saves the release's package into directory, removing what earlier downloads left
// there, and checks it against SHA256SUMS. It returns the file's path.
func Download(ctx context.Context, release Release, directory string) (string, error) {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	// The directory is systemd's CacheDirectory, which may be a mount point; only its
	// contents can go.
	entries, err := os.ReadDir(directory)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(directory, entry.Name())); err != nil {
			return "", err
		}
	}
	body, err := fetch(ctx, fmt.Sprintf("%s/download/v%s/%s", releases, release.Version, release.Name))
	if err != nil {
		return "", err
	}
	defer body.Close()

	path := filepath.Join(directory, release.Name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, err = io.Copy(io.MultiWriter(file, hash), body)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	if !bytes.Equal(hash.Sum(nil), release.sum) {
		os.Remove(path)
		return "", fmt.Errorf("%s does not match its SHA256SUMS entry", release.Name)
	}
	return path, nil
}

// Install hands the package file to the manager in a transient systemd unit and waits for it.
// The package's scripts restart the daemon, which would also kill an installer running in the
// daemon's own cgroup; the unit carries on when that restart kills systemd-run instead, and
// Install then returns nil.
func Install(manager *Manager, path string) error {
	args := append([]string{"--unit", installUnit, "--collect", "--quiet", "--wait", "--"}, manager.install...)
	output, err := exec.Command("systemd-run", append(args, path)...).CombinedOutput()
	if exitErr := (*exec.ExitError)(nil); errors.As(err, &exitErr) && !exitErr.Exited() {
		return nil
	}
	if err != nil {
		if message := bytes.TrimSpace(output); len(message) > 0 {
			return fmt.Errorf("%s: %s", err, message)
		}
		return fmt.Errorf("the installer failed (%w); see journalctl -u %s", err, installUnit)
	}
	return nil
}

func fetch(ctx context.Context, url string) (io.ReadCloser, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, response.Status)
	}
	return response.Body, nil
}
