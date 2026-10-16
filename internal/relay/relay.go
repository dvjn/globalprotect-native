// Package relay hands a callback URI from the URI handler process to the waiting login process.
package relay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// SocketPath is where a waiting login listens for the callback URI.
func SocketPath() (string, error) {
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		return "", errors.New("XDG_RUNTIME_DIR is not set")
	}
	return filepath.Join(runtimeDir, "globalprotect-native", "callback.sock"), nil
}

// Listener waits for one callback URI.
type Listener struct {
	listener net.Listener
	path     string
}

// ErrLoginPending means another gpn login is already waiting for its callback.
var ErrLoginPending = errors.New("another gpn login is already waiting for a callback")

// Listen claims the socket. It fails with ErrLoginPending if another login holds it.
func Listen(path string) (*Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if connection, err := net.Dial("unix", path); err == nil {
		connection.Close()
		return nil, ErrLoginPending
	}
	os.Remove(path)

	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	return &Listener{listener: listener, path: path}, nil
}

// Wait returns the first URI sent to the socket, or the context error.
func (listener *Listener) Wait(ctx context.Context) (string, error) {
	type result struct {
		uri string
		err error
	}
	results := make(chan result, 1)
	go func() {
		for {
			connection, err := listener.listener.Accept()
			if err != nil {
				results <- result{err: err}
				return
			}
			uri := readURI(connection)
			if uri != "" {
				results <- result{uri: uri}
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case received := <-results:
		return received.uri, received.err
	}
}

// readURI returns an empty string for connections that close without a URI,
// such as the probe Listen makes to detect another waiting login.
func readURI(connection net.Conn) string {
	defer connection.Close()
	line, _ := bufio.NewReader(connection).ReadString('\n')
	return strings.TrimSpace(line)
}

// Close releases the socket.
func (listener *Listener) Close() error {
	defer os.Remove(listener.path)
	return listener.listener.Close()
}

// ErrNoListener means no gpn login is waiting.
var ErrNoListener = errors.New("no gpn login is waiting")

// Send delivers the URI to a waiting login.
func Send(path, uri string) error {
	connection, err := net.Dial("unix", path)
	if err != nil {
		return ErrNoListener
	}
	defer connection.Close()
	if _, err := fmt.Fprintln(connection, uri); err != nil {
		return fmt.Errorf("send callback: %w", err)
	}
	return nil
}
