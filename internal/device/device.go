// Package device reads this machine's identity: the values the official client reports.
package device

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// fallbackClientVersion is reported when the official client is not installed.
const fallbackClientVersion = "6.2.8-1057"

// The SMBIOS values are readable by root only. Other users get them from systemd-hostnamed,
// which polkit allows only after admin authentication (auth_admin_keep), so it may prompt.
const (
	productUUIDPath = "/sys/class/dmi/id/product_uuid"
	serialPath      = "/sys/class/dmi/id/product_serial"
)

// ProductUUID returns the SMBIOS product UUID, which the official client sends as its host ID.
func ProductUUID() (string, error) {
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

// HardwareSerial returns the machine's serial number, such as a Dell service tag.
func HardwareSerial() (string, error) {
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
