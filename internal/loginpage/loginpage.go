// Package loginpage serves the portal's SAML form on localhost, so any browser,
// including a sandboxed Flatpak one, can open it.
package loginpage

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
)

// Server serves one HTML page at a random, unguessable URL.
type Server struct {
	URL    string
	server *http.Server
}

// Start begins serving page on 127.0.0.1 at a random port.
func Start(page []byte) (*Server, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		listener.Close()
		return nil, err
	}
	path := "/" + hex.EncodeToString(secret)

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+path, func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Write(page)
	})

	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	return &Server{URL: "http://" + listener.Addr().String() + path, server: server}, nil
}

// Close stops the server.
func (server *Server) Close() error {
	return server.server.Close()
}
