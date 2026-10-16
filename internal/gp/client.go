// Package gp speaks the GlobalProtect portal and gateway HTTPS protocol.
package gp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The portal and gateways reject requests without this user agent.
const userAgent = "PAN GlobalProtect"

// samlPassword is the placeholder password the Linux client sends with SAML credentials.
const samlPassword = "SAMLPASS"

// emptyCookie is the placeholder for a cookie the client does not have yet.
const emptyCookie = "empty"

// Identity describes this machine to the portal.
type Identity struct {
	HostID        string
	SerialNumber  string
	Computer      string
	OSVersion     string
	ClientVersion string
}

func (identity Identity) formValues() url.Values {
	return url.Values{
		"clientVer":       {"4100"},
		"clientos":        {"Linux"},
		"clientgpversion": {identity.ClientVersion},
		"computer":        {identity.Computer},
		"os-version":      {identity.OSVersion},
		"host-id":         {identity.HostID},
		"ipv6-support":    {"yes"},
	}
}

// Client sends requests to one portal or gateway.
type Client struct {
	HTTP     *http.Client
	Server   string
	Identity Identity
}

// NewClient returns a client for the server host name, such as slv.gpcloudservice.com.
func NewClient(server string, identity Identity) *Client {
	return &Client{
		HTTP:     &http.Client{Timeout: 30 * time.Second},
		Server:   server,
		Identity: identity,
	}
}

func (client *Client) post(ctx context.Context, path string, form url.Values) ([]byte, error) {
	endpoint := "https://" + client.Server + path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := client.HTTP.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if response.StatusCode == statusAuthenticationRejected {
		return nil, fmt.Errorf("%s: %w (HTTP %d)", path, ErrAuthenticationRejected, response.StatusCode)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d: %s", path, response.StatusCode, firstLine(body))
	}
	return body, nil
}

// ErrAuthenticationRejected means the portal or gateway no longer accepts the saved
// credentials, and the user has to log in through the browser again.
var ErrAuthenticationRejected = errors.New("authentication rejected")

// statusAuthenticationRejected is the HTTP status GlobalProtect answers stale cookies with.
const statusAuthenticationRejected = 512

func firstLine(body []byte) string {
	line, _, _ := strings.Cut(strings.TrimSpace(string(body)), "\n")
	if len(line) > 200 {
		return line[:200]
	}
	return line
}

func orEmptyCookie(cookie string) string {
	if cookie == "" {
		return emptyCookie
	}
	return cookie
}
