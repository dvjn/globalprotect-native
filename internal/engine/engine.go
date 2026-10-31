package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/tunnel"
)

const (
	keepaliveInterval = 10 * time.Second
	deadAfter         = 30 * time.Second
)

// Options are the caller's choices for one tunnel.
type Options struct {
	Settings config.Config
	// Log receives progress messages; nil discards them.
	Log *log.Logger
	// OnConnected is called once the tunnel carries traffic.
	OnConnected func(Connected)
}

// Connected describes a tunnel that carries traffic.
type Connected struct {
	Gateway   string
	ClientIP  string
	Transport string
}

// Run connects to the login's gateway and carries traffic until ctx ends, returning nil, or
// until the tunnel fails, returning why.
func Run(ctx context.Context, login Login, platform Platform, options Options) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	logger := orDiscard(options.Log)
	if err := platform.RemoveLeftovers(); err != nil {
		return fmt.Errorf("clean up after an earlier run: %w", err)
	}

	opened, err := OpenSession(ctx, login, platform.Dialer(), logger)
	if err != nil {
		return err
	}
	defer opened.LogOut()

	gatewayConfig, _, err := opened.Client.GatewayGetConfig(ctx, opened.Session)
	if err != nil {
		return err
	}
	if gatewayConfig.Quarantined {
		logger.Println("Warning: the gateway reports this machine as quarantined.")
	}
	settings := options.Settings
	if settings.HIP.Send {
		if err := sendHIPReportIfNeeded(ctx, opened, gatewayConfig.ClientIP, platform); err != nil {
			return err
		}
	}

	network, err := NewNetwork(opened.Gateway.Address, gatewayConfig, settings)
	if err != nil {
		return err
	}
	dog, err := newWatchdog(platform, network.Gateway, rekeyInterval(gatewayConfig.IdleTimeout))
	if err != nil {
		return err
	}
	if settings.HIP.Send {
		interval := time.Duration(opened.PortalConfig.HIPReportInterval) * time.Second
		go resendHIPReports(ctx, opened, gatewayConfig.ClientIP, platform, interval)
	}
	connected := func(transport string) {
		logger.Printf("Connected to %s over %s: %s, MTU %d, %s",
			opened.Gateway.Name, transport, gatewayConfig.ClientIP, network.MTU, network)
		options.OnConnected(Connected{Gateway: opened.Gateway.Name, ClientIP: gatewayConfig.ClientIP, Transport: transport})
	}

	if !settings.SSLOnly && gatewayConfig.ESP != nil {
		err := runESP(ctx, platform, network, *gatewayConfig.ESP, dog, connected)
		if !errors.Is(err, errESPUnavailable) {
			return err
		}
		logger.Println("Falling back to the SSL tunnel:", err)
	}
	return runSSL(ctx, platform, opened, gatewayConfig, network, dog, connected)
}

// A tunnel stops with one of these when it should be built again at once, without backoff.
var (
	errRekeyDue       = errors.New("rekey due")
	errNetworkChanged = errors.New("network changed")
)

// NeedsRebuild reports whether the tunnel ended because it has to be built again at once.
func NeedsRebuild(err error) bool {
	return errors.Is(err, errRekeyDue) || errors.Is(err, errNetworkChanged)
}

// watchdog notices, on every keepalive, that the tunnel must be rebuilt: its keys are about
// to expire, or the local address that reaches the gateway changed, as after a Wi-Fi switch.
type watchdog struct {
	platform Platform
	gateway  net.IP
	outer    net.IP
	rekeyAt  time.Time
}

func newWatchdog(platform Platform, gateway net.IP, rekeyAfter time.Duration) (watchdog, error) {
	outer, err := platform.OuterAddress(gateway)
	if err != nil {
		return watchdog{}, err
	}
	dog := watchdog{platform: platform, gateway: gateway, outer: outer}
	if rekeyAfter > 0 {
		dog.rekeyAt = time.Now().Add(rekeyAfter)
	}
	return dog, nil
}

func (dog watchdog) check() error {
	if !dog.rekeyAt.IsZero() && time.Now().After(dog.rekeyAt) {
		return errRekeyDue
	}
	current, err := dog.platform.OuterAddress(dog.gateway)
	if err != nil {
		return fmt.Errorf("%w: %w", errNetworkChanged, err)
	}
	if !current.Equal(dog.outer) {
		return fmt.Errorf("%w: local address %s is now %s", errNetworkChanged, dog.outer, current)
	}
	return nil
}

// rekeyInterval is when to rebuild the tunnel: a minute before the gateway's <timeout>, which
// OpenConnect treats as the rekey interval.
func rekeyInterval(timeoutSeconds int) time.Duration {
	timeout := time.Duration(timeoutSeconds) * time.Second
	if timeout <= 2*time.Minute {
		return 0
	}
	return timeout - time.Minute
}

// errESPUnavailable means ESP could not be set up or the gateway did not answer over it.
var errESPUnavailable = errors.New("ESP unavailable")

// espProbeTime is how long the engine waits for the first magic ping reply before falling back
// to SSL.
const espProbeTime = 10 * time.Second

// runESP carries traffic over ESP until ctx ends or the gateway stops answering.
func runESP(ctx context.Context, platform Platform, network Network, config gp.ESPConfig, dog watchdog, connected func(string)) error {
	esp, err := platform.OpenESP(network, config)
	if err != nil {
		return fmt.Errorf("%w: %w", errESPUnavailable, err)
	}
	defer esp.Close()

	if err := waitForMagicReply(esp, espProbeTime); err != nil {
		return fmt.Errorf("%w: %w", errESPUnavailable, err)
	}
	undo, err := platform.ApplyNetwork(network)
	if err != nil {
		return err
	}
	defer undo()

	connected("ESP")
	return keepESPAlive(ctx, esp, dog)
}

func waitForMagicReply(esp ESP, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for sequence := uint16(0); time.Now().Before(deadline); sequence++ {
		if err := esp.SendMagicPing(sequence); err != nil {
			return err
		}
		err := esp.ReadMagicReply()
		if err == nil {
			return nil
		}
		if !isTimeout(err) {
			return err
		}
	}
	return fmt.Errorf("no magic ping reply within %s", timeout)
}

// keepESPAlive pings the gateway every keepaliveInterval and gives up after deadAfter without a
// reply, or when the watchdog says the tunnel must be rebuilt.
func keepESPAlive(ctx context.Context, esp ESP, dog watchdog) error {
	var lastReply atomic.Int64
	lastReply.Store(time.Now().UnixNano())
	failures := make(chan error, 1)
	go func() {
		for ctx.Err() == nil {
			err := esp.ReadMagicReply()
			switch {
			case err == nil:
				lastReply.Store(time.Now().UnixNano())
			case !isTimeout(err):
				failures <- fmt.Errorf("read magic ping reply: %w", err)
				return
			}
		}
	}()

	keepalive := time.NewTicker(keepaliveInterval)
	defer keepalive.Stop()
	for sequence := uint16(1); ; sequence++ {
		select {
		case <-ctx.Done():
			return nil
		case err := <-failures:
			return err
		case <-keepalive.C:
			if quiet := time.Since(time.Unix(0, lastReply.Load())); quiet > deadAfter {
				return fmt.Errorf("ESP tunnel dead: no magic ping reply for %s", quiet.Round(time.Second))
			}
			if err := dog.check(); err != nil {
				return err
			}
			if err := esp.SendMagicPing(sequence); err != nil {
				return fmt.Errorf("send magic ping: %w", err)
			}
		}
	}
}

// runSSL carries traffic over the SSL tunnel through the platform's packet device.
func runSSL(ctx context.Context, platform Platform, opened Session, gatewayConfig gp.GatewayConfig, network Network, dog watchdog, connected func(string)) error {
	device, err := platform.OpenDevice(network)
	if err != nil {
		return err
	}
	defer device.Close()

	sslTunnel, err := tunnel.DialSSL(ctx, platform.Dialer(), opened.Gateway.Address, gatewayConfig.SSLTunnelPath,
		opened.Session.Username, opened.Session.AuthCookie)
	if err != nil {
		return err
	}
	defer sslTunnel.Close()

	undo, err := platform.ApplyNetwork(network)
	if err != nil {
		return err
	}
	defer undo()

	connected("SSL")
	return forwardPackets(ctx, device, sslTunnel, network.MTU, dog)
}

// forwardPackets copies packets both ways until ctx ends, the tunnel fails or goes quiet, or the
// watchdog says the tunnel must be rebuilt.
func forwardPackets(ctx context.Context, device io.ReadWriter, sslTunnel *tunnel.SSL, mtu int, dog watchdog) error {
	var lastReceived atomic.Int64
	lastReceived.Store(time.Now().UnixNano())
	failures := make(chan error, 2)

	go func() {
		packet := make([]byte, mtu)
		for {
			length, err := device.Read(packet)
			if err != nil {
				failures <- fmt.Errorf("read the tunnel device: %w", err)
				return
			}
			if err := sslTunnel.WritePacket(packet[:length]); err != nil {
				failures <- fmt.Errorf("send to gateway: %w", err)
				return
			}
		}
	}()

	go func() {
		for {
			packet, err := sslTunnel.ReadPacket()
			if err != nil {
				failures <- fmt.Errorf("receive from gateway: %w", err)
				return
			}
			lastReceived.Store(time.Now().UnixNano())
			if packet == nil {
				continue
			}
			if _, err := device.Write(packet); err != nil {
				failures <- fmt.Errorf("write the tunnel device: %w", err)
				return
			}
		}
	}()

	keepalive := time.NewTicker(keepaliveInterval)
	defer keepalive.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-failures:
			return err
		case <-keepalive.C:
			if quiet := time.Since(time.Unix(0, lastReceived.Load())); quiet > deadAfter {
				return fmt.Errorf("tunnel dead: nothing received for %s", quiet.Round(time.Second))
			}
			if err := dog.check(); err != nil {
				return err
			}
			if err := sslTunnel.SendKeepalive(); err != nil {
				return fmt.Errorf("send keepalive: %w", err)
			}
		}
	}
}
