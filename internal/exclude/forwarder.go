package exclude

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const upstreamTimeout = 5 * time.Second

// Forwarder relays DNS queries to the tunnel's servers. Before it returns an answer for an
// excluded name, it adds the answer's addresses to the firewall set, so the connection that
// follows already leaves outside the tunnel.
type Forwarder struct {
	udp       *net.UDPConn
	tcp       *net.TCPListener
	upstreams []string
	domains   Domains
	firewall  *Firewall
}

// StartForwarder listens on address port 53 over UDP and TCP.
func StartForwarder(address net.IP, upstreams []string, domains Domains, firewall *Firewall) (*Forwarder, error) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: address, Port: 53})
	if err != nil {
		return nil, fmt.Errorf("DNS forwarder: %w", err)
	}
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: address, Port: 53})
	if err != nil {
		udp.Close()
		return nil, fmt.Errorf("DNS forwarder: %w", err)
	}

	forwarder := &Forwarder{udp: udp, tcp: tcp, upstreams: upstreams, domains: domains, firewall: firewall}
	go forwarder.serveUDP()
	go forwarder.serveTCP()
	return forwarder, nil
}

// Close stops listening.
func (forwarder *Forwarder) Close() error {
	return errors.Join(forwarder.udp.Close(), forwarder.tcp.Close())
}

func (forwarder *Forwarder) serveUDP() {
	for {
		buffer := make([]byte, 65535)
		length, client, err := forwarder.udp.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		go func(query []byte) {
			answer, err := forwarder.exchange("udp", query)
			if err != nil {
				fmt.Fprintln(os.Stderr, "DNS forwarder:", err)
				return
			}
			forwarder.udp.WriteToUDP(answer, client)
		}(buffer[:length])
	}
}

func (forwarder *Forwarder) serveTCP() {
	for {
		connection, err := forwarder.tcp.Accept()
		if err != nil {
			return
		}
		go forwarder.serveTCPConnection(connection)
	}
}

func (forwarder *Forwarder) serveTCPConnection(connection net.Conn) {
	defer connection.Close()
	for {
		connection.SetDeadline(time.Now().Add(30 * time.Second))
		query, err := readTCPMessage(connection)
		if err != nil {
			return
		}
		answer, err := forwarder.exchange("tcp", query)
		if err != nil {
			fmt.Fprintln(os.Stderr, "DNS forwarder:", err)
			return
		}
		if err := writeTCPMessage(connection, answer); err != nil {
			return
		}
	}
}

// exchange asks each upstream in turn and records excluded addresses from the first answer.
func (forwarder *Forwarder) exchange(network string, query []byte) ([]byte, error) {
	var errs []error
	for _, upstream := range forwarder.upstreams {
		answer, err := ask(network, net.JoinHostPort(upstream, "53"), query)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := forwarder.recordExcluded(answer); err != nil {
			fmt.Fprintln(os.Stderr, "DNS forwarder:", err)
		}
		return answer, nil
	}
	return nil, errors.Join(errs...)
}

func ask(network, upstream string, query []byte) ([]byte, error) {
	connection, err := net.DialTimeout(network, upstream, upstreamTimeout)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(upstreamTimeout))

	if network == "tcp" {
		if err := writeTCPMessage(connection, query); err != nil {
			return nil, err
		}
		return readTCPMessage(connection)
	}
	if _, err := connection.Write(query); err != nil {
		return nil, err
	}
	answer := make([]byte, 65535)
	length, err := connection.Read(answer)
	return answer[:length], err
}

// recordExcluded adds the IPv4 addresses of an answer to the firewall set when the question is excluded.
func (forwarder *Forwarder) recordExcluded(answer []byte) error {
	addresses, ttl, excluded, err := excludedAddresses(answer, forwarder.domains)
	if err != nil || !excluded {
		return err
	}
	return forwarder.firewall.Add(addresses, ttl)
}

// excludedAddresses returns the A records of answer, with their shortest TTL, when its question is excluded.
func excludedAddresses(answer []byte, domains Domains) ([]net.IP, time.Duration, bool, error) {
	var parser dnsmessage.Parser
	if _, err := parser.Start(answer); err != nil {
		return nil, 0, false, err
	}
	question, err := parser.Question()
	if err != nil {
		return nil, 0, false, err
	}
	if !domains.Match(question.Name.String()) {
		return nil, 0, false, nil
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, 0, true, err
	}

	var addresses []net.IP
	var ttl time.Duration
	for {
		header, err := parser.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return addresses, ttl, true, nil
		}
		if err != nil {
			return addresses, ttl, true, err
		}
		if header.Type != dnsmessage.TypeA {
			if err := parser.SkipAnswer(); err != nil {
				return addresses, ttl, true, err
			}
			continue
		}
		record, err := parser.AResource()
		if err != nil {
			return addresses, ttl, true, err
		}
		addresses = append(addresses, net.IP(record.A[:]))
		recordTTL := time.Duration(header.TTL) * time.Second
		if ttl == 0 || recordTTL < ttl {
			ttl = recordTTL
		}
	}
}

// DNS over TCP prefixes each message with its length as two bytes (RFC 1035, section 4.2.2).
func readTCPMessage(reader io.Reader) ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return nil, err
	}
	message := make([]byte, binary.BigEndian.Uint16(length[:]))
	_, err := io.ReadFull(reader, message)
	return message, err
}

func writeTCPMessage(writer io.Writer, message []byte) error {
	_, err := writer.Write(binary.BigEndian.AppendUint16(nil, uint16(len(message))))
	if err != nil {
		return err
	}
	_, err = writer.Write(message)
	return err
}
