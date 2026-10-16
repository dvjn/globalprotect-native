package gp

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// CallbackScheme is the URI scheme the browser opens when SAML login finishes.
const CallbackScheme = "globalprotectcallback"

// Callback holds the credentials from a CAS callback URI.
type Callback struct {
	Username string
	Token    string
}

// ParseCallback decodes globalprotectcallback:cas-as=1&un=<user>&token=<JWT>.
func ParseCallback(uri string) (Callback, error) {
	payload, found := strings.CutPrefix(uri, CallbackScheme+":")
	if !found {
		return Callback{}, fmt.Errorf("not a %s URI", CallbackScheme)
	}
	payload = strings.TrimLeft(payload, "/")
	if !strings.HasPrefix(payload, "cas-as") {
		return Callback{}, errors.New("callback is not a CAS callback; only CAS login is supported")
	}

	if unescaped, err := url.QueryUnescape(payload); err == nil {
		payload = unescaped
	}
	values, err := url.ParseQuery(payload)
	if err != nil {
		return Callback{}, fmt.Errorf("parse CAS callback: %w", err)
	}

	callback := Callback{Username: values.Get("un"), Token: values.Get("token")}
	if callback.Username == "" || callback.Token == "" {
		return Callback{}, errors.New("CAS callback has no username or token")
	}
	return callback, nil
}
