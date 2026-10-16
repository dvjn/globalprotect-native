// Package userdir finds the invoking user's directories, also when gpn runs under sudo.
package userdir

import (
	"os"
	"os/user"
)

// Home is the home directory of the user who ran gpn, looking through sudo.
func Home() (string, error) {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" && os.Geteuid() == 0 {
		account, err := user.Lookup(sudoUser)
		if err != nil {
			return "", err
		}
		return account.HomeDir, nil
	}
	return os.UserHomeDir()
}
