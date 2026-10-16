package gp

import (
	"regexp"
	"strings"
)

var leafElement = regexp.MustCompile(`<([A-Za-z0-9_-]+)>([^<]*)</([A-Za-z0-9_-]+)>`)

var secretNameParts = []string{"cookie", "token", "key", "secret", "passw", "passcode", "hash", "host-id", "serial", "spi"}

// ESP keys sit in <val> elements under <ekey-c2s>, <akey-s2c> and the like.
var secretNames = map[string]bool{"val": true}

// Redact replaces the text of XML elements whose names suggest secrets, so a response can be stored as a fixture.
func Redact(body []byte) []byte {
	return leafElement.ReplaceAllFunc(body, func(element []byte) []byte {
		parts := leafElement.FindSubmatch(element)
		name := strings.ToLower(string(parts[1]))
		if string(parts[1]) != string(parts[3]) || len(parts[2]) == 0 || !isSecretName(name) {
			return element
		}
		return []byte("<" + string(parts[1]) + ">REDACTED</" + string(parts[1]) + ">")
	})
}

func isSecretName(name string) bool {
	if secretNames[name] {
		return true
	}
	for _, part := range secretNameParts {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}
