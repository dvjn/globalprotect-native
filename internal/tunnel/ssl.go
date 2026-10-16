package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
)

const startTunnel = "START_TUNNEL"

// SSL is the TCP fallback tunnel: IP packets framed inside one TLS connection to the gateway.
type SSL struct {
	connection *tls.Conn
	reader     *bufio.Reader
	writeLock  sync.Mutex
	buffer     []byte
}

// DialSSL opens the tunnel at path on the gateway server for the session's user and auth cookie.
func DialSSL(ctx context.Context, server, path, username, authCookie string) (*SSL, error) {
	dialer := &tls.Dialer{Config: &tls.Config{ServerName: server}}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(server, "443"))
	if err != nil {
		return nil, err
	}
	tlsConnection := connection.(*tls.Conn)

	request := fmt.Sprintf("GET %s?user=%s&authcookie=%s HTTP/1.1\r\n\r\n", path, url.QueryEscape(username), url.QueryEscape(authCookie))
	if _, err := io.WriteString(tlsConnection, request); err != nil {
		tlsConnection.Close()
		return nil, err
	}

	reader := bufio.NewReaderSize(tlsConnection, 64<<10)
	reply := make([]byte, len(startTunnel))
	if _, err := io.ReadFull(reader, reply); err != nil {
		tlsConnection.Close()
		return nil, fmt.Errorf("gateway closed the tunnel request: %w", err)
	}
	if string(reply) != startTunnel {
		rest, _ := reader.ReadString('\n')
		tlsConnection.Close()
		return nil, fmt.Errorf("gateway refused the tunnel: %q", string(reply)+rest)
	}

	return &SSL{connection: tlsConnection, reader: reader, buffer: make([]byte, 64<<10)}, nil
}

// ReadPacket returns the next IP packet from the gateway, or nil for a keepalive.
// The packet is only valid until the next call.
func (tunnel *SSL) ReadPacket() ([]byte, error) {
	return readFrame(tunnel.reader, tunnel.buffer)
}

// WritePacket sends one IP packet to the gateway.
func (tunnel *SSL) WritePacket(packet []byte) error {
	return tunnel.write(encodeFrame(packet))
}

// SendKeepalive asks the gateway for a keepalive reply.
func (tunnel *SSL) SendKeepalive() error {
	return tunnel.write(keepaliveFrame())
}

func (tunnel *SSL) write(frame []byte) error {
	tunnel.writeLock.Lock()
	defer tunnel.writeLock.Unlock()
	_, err := tunnel.connection.Write(frame)
	return err
}

// Close ends the tunnel.
func (tunnel *SSL) Close() error {
	return tunnel.connection.Close()
}
