package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/dvjn/globalprotect-native/internal/gp"
)

type gatewaySession struct {
	client       *gp.Client
	session      gp.Session
	gateway      gp.Gateway
	identity     gp.Identity
	portalConfig gp.PortalConfig
}

// openGatewaySession logs in to the chosen gateway, or the fastest one, with the saved portal
// cookie. A missing or rejected cookie comes back as gp.ErrAuthenticationRejected.
func openGatewaySession(ctx context.Context, env environment) (gatewaySession, error) {
	portal, saved, err := env.portalClient()
	if err != nil {
		return gatewaySession{}, err
	}
	_, gatewayName, err := env.target(saved)
	if err != nil {
		return gatewaySession{}, err
	}
	cookie, found := saved.Portals[portal.Server]
	if !found {
		return gatewaySession{}, fmt.Errorf("not logged in to %s: %w", portal.Server, gp.ErrAuthenticationRejected)
	}

	portalConfig, _, err := portal.PortalGetConfig(ctx, cookieCredential(cookie))
	if err != nil {
		return gatewaySession{}, fmt.Errorf("portal %s: %w", portal.Server, err)
	}
	var gateway gp.Gateway
	if gatewayName == "" {
		gateway, err = fastestGateway(ctx, portalConfig.Gateways)
	} else {
		gateway, err = findGateway(portalConfig.Gateways, gatewayName)
	}
	if err != nil {
		return gatewaySession{}, err
	}

	client := gp.NewClient(gateway.Address, portal.Identity)
	session, err := client.GatewayLogin(ctx, gp.Credential{
		Username:               cookie.Username,
		UserAuthCookie:         portalConfig.UserAuthCookie,
		PrelogonUserAuthCookie: portalConfig.PrelogonUserAuthCookie,
	})
	if err != nil {
		return gatewaySession{}, err
	}
	return gatewaySession{client: client, session: session, gateway: gateway, identity: portal.Identity, portalConfig: portalConfig}, nil
}

func (opened gatewaySession) logOut() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := opened.client.GatewayLogout(ctx, opened.session); err != nil {
		fmt.Fprintln(os.Stderr, "Gateway logout failed:", err)
		return
	}
	fmt.Fprintln(os.Stderr, "Logged out of the gateway.")
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
func fastestGateway(ctx context.Context, gateways []gp.Gateway) (gp.Gateway, error) {
	if len(gateways) == 0 {
		return gp.Gateway{}, fmt.Errorf("the portal offers no gateways")
	}
	ctx, cancel := context.WithTimeout(ctx, gatewayProbeTimeout)
	defer cancel()

	answers := make(chan gp.Gateway, len(gateways))
	for _, gateway := range gateways {
		go func() {
			var dialer net.Dialer
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
		fmt.Fprintf(os.Stderr, "Fastest gateway: %s (%s)\n", gateway.Name, gateway.Address)
		return gateway, nil
	case <-ctx.Done():
		return gp.Gateway{}, fmt.Errorf("no gateway answered within %s", gatewayProbeTimeout)
	}
}
