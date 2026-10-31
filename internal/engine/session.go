package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/hip"
)

// Login is what opens a gateway session: the portal with the user's saved login, and the
// gateway the user chose by name or address, or "" for the fastest one.
type Login struct {
	Portal     string
	Gateway    string
	Identity   gp.Identity
	Credential gp.Credential
	// HIP, when it sets anything, is reported instead of what the platform detects. Its host
	// ID, serial number, computer, OS and client version also log in, so the login and the
	// report agree.
	HIP hip.Profile
}

// identity is the login's identity with what its HIP profile overrides.
func (login Login) identity() gp.Identity {
	return WithHIPProfile(login.Identity, login.HIP)
}

// WithHIPProfile is identity with what profile overrides: its host ID, serial number,
// computer, OS and client version. Every request to the portal and gateways uses it, so they
// all see the machine the HIP report describes.
func WithHIPProfile(identity gp.Identity, profile hip.Profile) gp.Identity {
	merged := profile.Over(identityProfile(identity))
	return gp.Identity{
		HostID:        merged.HostID,
		SerialNumber:  merged.SerialNumber,
		Computer:      merged.Computer,
		OSVersion:     merged.OS,
		ClientVersion: merged.ClientVersion,
	}
}

// Session is a logged-in gateway.
type Session struct {
	Client       *gp.Client
	Session      gp.Session
	Gateway      gp.Gateway
	PortalConfig gp.PortalConfig
	// HIP is the login's HIP profile.
	HIP hip.Profile
	log *log.Logger
}

// OpenSession logs in to the chosen gateway, or the fastest one, with the saved portal login,
// connecting with dialer, or the default one when it is nil, and telling logger, if any, how it
// went. A rejected login comes back as gp.ErrAuthenticationRejected.
func OpenSession(ctx context.Context, login Login, dialer *net.Dialer, logger *log.Logger) (Session, error) {
	logger = orDiscard(logger)
	identity := login.identity()
	portal := newClient(login.Portal, identity, dialer)
	portalConfig, _, err := portal.PortalGetConfig(ctx, login.Credential)
	if err != nil {
		return Session{}, fmt.Errorf("portal %s: %w", portal.Server, err)
	}
	var gateway gp.Gateway
	if login.Gateway == "" {
		gateway, err = fastestGateway(ctx, portalConfig.Gateways, dialer, logger)
	} else {
		gateway, err = findGateway(portalConfig.Gateways, login.Gateway)
	}
	if err != nil {
		return Session{}, err
	}

	client := newClient(gateway.Address, identity, dialer)
	session, err := client.GatewayLogin(ctx, gp.Credential{
		Username:               login.Credential.Username,
		UserAuthCookie:         portalConfig.UserAuthCookie,
		PrelogonUserAuthCookie: portalConfig.PrelogonUserAuthCookie,
	})
	if err != nil {
		return Session{}, err
	}
	return Session{Client: client, Session: session, Gateway: gateway, PortalConfig: portalConfig, HIP: login.HIP, log: logger}, nil
}

func newClient(server string, identity gp.Identity, dialer *net.Dialer) *gp.Client {
	client := gp.NewClient(server, identity)
	if dialer != nil {
		client.UseDialer(dialer)
	}
	return client
}

// LogOut ends the gateway session.
func (opened Session) LogOut() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := opened.Client.GatewayLogout(ctx, opened.Session); err != nil {
		opened.log.Println("Gateway logout failed:", err)
		return
	}
	opened.log.Println("Logged out of the gateway.")
}

func findGateway(gateways []gp.Gateway, nameOrAddress string) (gp.Gateway, error) {
	var names []string
	for _, gateway := range gateways {
		if strings.EqualFold(gateway.Name, nameOrAddress) || strings.EqualFold(gateway.Address, nameOrAddress) {
			return gateway, nil
		}
		names = append(names, gateway.Name)
	}
	return gp.Gateway{}, fmt.Errorf("no gateway %q; choose one of: %s", nameOrAddress, strings.Join(names, ", "))
}

// gatewayProbeTimeout bounds how long fastestGateway waits for a slow gateway.
const gatewayProbeTimeout = 3 * time.Second

// fastestGateway picks the gateway whose HTTPS port accepts a connection first.
func fastestGateway(ctx context.Context, gateways []gp.Gateway, dialer *net.Dialer, logger *log.Logger) (gp.Gateway, error) {
	if len(gateways) == 0 {
		return gp.Gateway{}, fmt.Errorf("the portal offers no gateways")
	}
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	ctx, cancel := context.WithTimeout(ctx, gatewayProbeTimeout)
	defer cancel()

	answers := make(chan gp.Gateway, len(gateways))
	for _, gateway := range gateways {
		go func() {
			connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(gateway.Address, "443"))
			if err != nil {
				return
			}
			connection.Close()
			answers <- gateway
		}()
	}
	select {
	case gateway := <-answers:
		logger.Printf("Fastest gateway: %s (%s)", gateway.Name, gateway.Address)
		return gateway, nil
	case <-ctx.Done():
		return gp.Gateway{}, fmt.Errorf("no gateway answered within %s", gatewayProbeTimeout)
	}
}
