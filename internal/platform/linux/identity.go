package linux

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/gp"
)

// fallbackClientVersion is reported when the official client is not installed.
const fallbackClientVersion = "6.2.8-1057"

// The SMBIOS values are readable by root only. Other users get them from systemd-hostnamed,
// which polkit allows only after admin authentication (auth_admin_keep), so it may prompt.
const (
	productUUIDPath = "/sys/class/dmi/id/product_uuid"
	serialPath      = "/sys/class/dmi/id/product_serial"
)

// productUUID returns the SMBIOS product UUID, which the official client sends as its host ID.
func productUUID() (string, error) {
	if os.Geteuid() == 0 {
		return readSysfs(productUUIDPath)
	}
	var reply struct {
		Data [][]byte `json:"data"`
	}
	if err := callHostnamed(&reply, "GetProductUUID", "b", "false"); err != nil {
		return "", err
	}
	if len(reply.Data) != 1 || len(reply.Data[0]) != 16 {
		return "", fmt.Errorf("hostnamed returned no 16-byte product UUID")
	}
	id := reply.Data[0]
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16]), nil
}

// hardwareSerial returns the machine's serial number, such as a Dell service tag.
func hardwareSerial() (string, error) {
	if os.Geteuid() == 0 {
		return readSysfs(serialPath)
	}
	var reply struct {
		Data []string `json:"data"`
	}
	if err := callHostnamed(&reply, "GetHardwareSerial"); err != nil {
		return "", err
	}
	if len(reply.Data) != 1 {
		return "", fmt.Errorf("hostnamed returned no hardware serial")
	}
	return reply.Data[0], nil
}

func readSysfs(path string) (string, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(value)), nil
}

// ClientVersion returns the installed official client's version, such as "6.2.8-1057".
func ClientVersion() string {
	for _, name := range []string{"GlobalProtect_UI_rpm", "GlobalProtect_rpm"} {
		output, err := exec.Command("rpm", "-q", "--queryformat", "%{VERSION}-%{RELEASE}", name).Output()
		if err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	return fallbackClientVersion
}

func callHostnamed(reply any, method string, arguments ...string) error {
	command := append([]string{"--json=short", "call", "org.freedesktop.hostname1", "/org/freedesktop/hostname1",
		"org.freedesktop.hostname1", method}, arguments...)
	output, err := exec.Command("busctl", command...).Output()
	if err != nil {
		return fmt.Errorf("hostnamed %s: %w", method, err)
	}
	return json.Unmarshal(output, reply)
}

// Identify describes the machine as the official Linux client does, with the device's own
// identity when the settings ask for it.
func Identify(clientVersion string) func(config.Config, string) (gp.Identity, error) {
	return func(settings config.Config, hostID string) (gp.Identity, error) {
		serialNumber := ""
		if settings.DeviceIdentity {
			var err error
			if hostID, err = productUUID(); err != nil {
				return gp.Identity{}, fmt.Errorf("read the device identity (set device_identity: false to skip): %w", err)
			}
			if serialNumber, err = hardwareSerial(); err != nil {
				return gp.Identity{}, fmt.Errorf("read the device identity (set device_identity: false to skip): %w", err)
			}
		}
		computer, err := os.Hostname()
		if err != nil {
			return gp.Identity{}, err
		}
		return gp.Identity{
			HostID:        hostID,
			SerialNumber:  serialNumber,
			Computer:      computer,
			OSVersion:     osName(),
			ClientVersion: clientVersion,
		}, nil
	}
}

// osName describes the OS the way the official Linux client does, such as "Linux Fedora 44".
func osName() string {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return "Linux"
	}
	defer file.Close()

	release := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if key, value, found := strings.Cut(scanner.Text(), "="); found {
			release[key] = strings.Trim(value, `"`)
		}
	}
	distribution := strings.TrimSuffix(release["NAME"], " Linux")
	return strings.TrimSpace("Linux " + distribution + " " + release["VERSION_ID"])
}
