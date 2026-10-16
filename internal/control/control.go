// Package control is the protocol between the gpn daemon and its clients: one JSON object per
// line over a Unix socket. A client sends one request per connection; the daemon answers with
// one response, or with a stream of them for "watch".
package control

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// DefaultSocket is where the daemon listens. GPN_SOCKET overrides it for clients.
const DefaultSocket = "/run/globalprotect-native/control.sock"

// Commands a client can send.
const (
	CommandStatus     = "status"
	CommandWatch      = "watch"
	CommandConnect    = "connect"
	CommandDisconnect = "disconnect"
	CommandReconnect  = "reconnect"
	CommandPrelogin   = "prelogin"
	CommandLogin      = "login"
)

// States the daemon reports.
const (
	StateDisconnected = "disconnected"
	StateConnecting   = "connecting"
	StateConnected    = "connected"
	StateReconnecting = "reconnecting"
	StateNeedsLogin   = "needs-login"
	StateFailed       = "failed"
)

// Request is what a client asks. Username and Token come from the browser login. Portal and
// Gateway, on connect and prelogin, change the daemon's saved choice; empty keeps it.
type Request struct {
	Command  string `json:"command"`
	Username string `json:"username,omitempty"`
	Token    string `json:"token,omitempty"`
	Portal   string `json:"portal,omitempty"`
	Gateway  string `json:"gateway,omitempty"`
}

// Status is the daemon's view of the tunnel.
type Status struct {
	State     string    `json:"state"`
	Gateway   string    `json:"gateway,omitempty"`
	ClientIP  string    `json:"client_ip,omitempty"`
	Transport string    `json:"transport,omitempty"`
	Error     string    `json:"error,omitempty"`
	Since     time.Time `json:"since"`
}

// Response answers a request. LoginPage and LoginTimeout answer "prelogin".
type Response struct {
	Error        string        `json:"error,omitempty"`
	Status       *Status       `json:"status,omitempty"`
	LoginPage    []byte        `json:"login_page,omitempty"`
	LoginTimeout time.Duration `json:"login_timeout,omitempty"`
}

// SocketPath is the socket clients connect to.
func SocketPath() string {
	if path := os.Getenv("GPN_SOCKET"); path != "" {
		return path
	}
	return DefaultSocket
}

// Conn is one client connection to the daemon.
type Conn struct {
	connection net.Conn
	reader     *bufio.Reader
}

// Dial connects to the daemon.
func Dial() (*Conn, error) {
	path := SocketPath()
	connection, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("reach the gpn daemon at %s: %w", path, err)
	}
	return &Conn{connection: connection, reader: bufio.NewReader(connection)}, nil
}

// Send writes a request.
func (conn *Conn) Send(request Request) error {
	return writeLine(conn.connection, request)
}

// Receive reads the next response. A response carrying an error comes back as that error.
func (conn *Conn) Receive() (Response, error) {
	var response Response
	if err := readLine(conn.reader, &response); err != nil {
		return Response{}, err
	}
	if response.Error != "" {
		return response, fmt.Errorf("gpn daemon: %s", response.Error)
	}
	return response, nil
}

// Close ends the connection.
func (conn *Conn) Close() error {
	return conn.connection.Close()
}

// Call sends one request and returns its one response.
func Call(request Request) (Response, error) {
	conn, err := Dial()
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	if err := conn.Send(request); err != nil {
		return Response{}, err
	}
	return conn.Receive()
}

// ReadRequest reads a client's request on the daemon side.
func ReadRequest(reader *bufio.Reader) (Request, error) {
	var request Request
	err := readLine(reader, &request)
	return request, err
}

// WriteResponse sends a response on the daemon side.
func WriteResponse(connection net.Conn, response Response) error {
	return writeLine(connection, response)
}

func writeLine(connection net.Conn, value any) error {
	line, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = connection.Write(append(line, '\n'))
	return err
}

func readLine(reader *bufio.Reader, value any) error {
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return err
	}
	return json.Unmarshal(line, value)
}
