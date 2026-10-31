package desktop

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/dvjn/globalprotect-native/internal/control"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/loginpage"
	"github.com/dvjn/globalprotect-native/internal/relay"
)

// BrowserLogin opens the portal's login page in the browser and hands the result to the daemon.
// An empty portal means the one the daemon already knows. It claims the callback socket before
// asking for a login page, so a second login fails with relay.ErrLoginPending without disturbing
// the first.
func BrowserLogin(ctx context.Context, portal string) error {
	socketPath, err := relay.SocketPath()
	if err != nil {
		return err
	}
	listener, err := relay.Listen(socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()

	response, err := control.Call(control.Request{Command: control.CommandPrelogin, Portal: portal})
	if err != nil {
		return err
	}
	callbackURI, err := waitForBrowserLogin(ctx, listener, response.LoginPage, response.LoginTimeout)
	if err != nil {
		return err
	}
	callback, err := gp.ParseCallback(callbackURI)
	if err != nil {
		return err
	}
	if _, err := control.Call(control.Request{Command: control.CommandLogin, Username: callback.Username, Token: callback.Token}); err != nil {
		return err
	}
	fmt.Println("Logged in as", callback.Username)
	return nil
}

// waitForBrowserLogin serves page on localhost, opens it, and waits for the callback URI that
// `gpn callback` relays from the browser.
func waitForBrowserLogin(ctx context.Context, listener *relay.Listener, page []byte, timeout time.Duration) (string, error) {
	server, err := loginpage.Start(page)
	if err != nil {
		return "", err
	}
	defer server.Close()

	fmt.Fprintln(os.Stderr, "Opening the browser for login:", server.URL)
	if err := exec.Command("xdg-open", server.URL).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Could not open the browser; open the URL above by hand.")
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	uri, err := listener.Wait(ctx)
	if err != nil {
		return "", fmt.Errorf("waiting for the browser login: %w", err)
	}
	return uri, nil
}
