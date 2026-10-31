package engine

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/gp"
)

// reconnectDelays are the waits between failed attempts; the last one repeats.
var reconnectDelays = []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second, time.Minute}

// stableAfter is how long a tunnel has to hold before a later failure starts the delays over.
const stableAfter = time.Minute

// Permanent marks err as one that retrying cannot fix, so the Supervisor gives up on it.
func Permanent(err error) error {
	return permanentError{err}
}

type permanentError struct{ err error }

func (permanent permanentError) Error() string { return permanent.err.Error() }
func (permanent permanentError) Unwrap() error { return permanent.err }

// NeedsLogin reports whether the tunnel stopped because the portal or gateway rejected the
// saved login.
func NeedsLogin(err error) bool {
	return errors.Is(err, gp.ErrAuthenticationRejected)
}

func isPermanent(err error) bool {
	var permanent permanentError
	return errors.As(err, &permanent)
}

// Supervisor keeps a tunnel up: one that fails is built again after a delay, and one that needs
// rebuilding (rekey, network change, Restart) at once.
type Supervisor struct {
	// Prepare returns the login and settings for the next tunnel. It runs before every attempt,
	// so edits to the settings apply on the next reconnect.
	Prepare  func() (Login, config.Config, error)
	Platform Platform
	// Log receives progress messages; nil discards them.
	Log *log.Logger
	// OnConnected is called whenever a tunnel carries traffic, and OnReconnecting whenever one
	// ended and the next is on its way.
	OnConnected    func(Connected)
	OnReconnecting func(reason string)

	lock sync.Mutex
	// running is set while Run runs; restart ends the current attempt, and wake cuts short the
	// wait before the next one.
	running bool
	restart context.CancelFunc
	wake    chan struct{}
}

// Run keeps tunnels up until ctx ends, returning nil, or until retrying cannot help: the
// portal rejected the login (gp.ErrAuthenticationRejected), or Prepare or the tunnel failed
// with a Permanent error.
func (supervisor *Supervisor) Run(ctx context.Context) error {
	logger := orDiscard(supervisor.Log)
	wake := make(chan struct{}, 1)
	supervisor.lock.Lock()
	supervisor.running, supervisor.wake = true, wake
	supervisor.lock.Unlock()
	defer func() {
		supervisor.lock.Lock()
		supervisor.running, supervisor.restart, supervisor.wake = false, nil, nil
		supervisor.lock.Unlock()
	}()

	failures := 0
	for {
		attempt, restart := context.WithCancel(ctx)
		supervisor.lock.Lock()
		supervisor.restart = restart
		select {
		case <-wake:
		default:
		}
		supervisor.lock.Unlock()

		var connectedAt time.Time
		err := supervisor.attempt(attempt, func(connected Connected) {
			connectedAt = time.Now()
			supervisor.OnConnected(connected)
		})
		restart()

		switch {
		case ctx.Err() != nil:
			return nil
		case NeedsLogin(err), isPermanent(err):
			return err
		}

		if !connectedAt.IsZero() && time.Since(connectedAt) > stableAfter {
			failures = 0
		}
		var delay time.Duration
		reason := "restart requested"
		if err != nil {
			reason = err.Error()
			if !NeedsRebuild(err) {
				delay = reconnectDelays[min(failures, len(reconnectDelays)-1)]
				failures++
			}
		}
		logger.Printf("Reconnecting in %s: %s", delay, reason)
		supervisor.OnReconnecting(reason)

		select {
		case <-ctx.Done():
			return nil
		case <-wake:
		case <-time.After(delay):
		}
	}
}

func (supervisor *Supervisor) attempt(ctx context.Context, onConnected func(Connected)) error {
	login, settings, err := supervisor.Prepare()
	if err != nil {
		return err
	}
	return Run(ctx, login, supervisor.Platform, Options{Settings: settings, Log: supervisor.Log, OnConnected: onConnected})
}

// Restart builds the tunnel again at once, as after resume, ending the current one or the wait
// before the next. It reports whether Run is running.
func (supervisor *Supervisor) Restart() bool {
	supervisor.lock.Lock()
	defer supervisor.lock.Unlock()
	if !supervisor.running {
		return false
	}
	if supervisor.restart != nil {
		supervisor.restart()
	}
	select {
	case supervisor.wake <- struct{}{}:
	default:
	}
	return true
}
