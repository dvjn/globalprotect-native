package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/gp"
)

func TestSupervisorStopsWhenRetryingCannotHelp(t *testing.T) {
	notConfigured := errors.New("not configured")
	for name, failure := range map[string]error{
		"permanent":      fmt.Errorf("load: %w", Permanent(notConfigured)),
		"login rejected": fmt.Errorf("portal: %w", gp.ErrAuthenticationRejected),
	} {
		supervisor := &Supervisor{
			Prepare: func() (Login, config.Config, error) { return Login{}, config.Config{}, failure },
			OnReconnecting: func(reason string) {
				t.Errorf("%s: reconnecting after %s", name, reason)
			},
		}
		if err := supervisor.Run(context.Background()); err != failure {
			t.Errorf("%s: got %v, want %v", name, err, failure)
		}
		if supervisor.Restart() {
			t.Errorf("%s: Restart reports a running supervisor after Run returned", name)
		}
	}
	if !errors.Is(Permanent(notConfigured), notConfigured) {
		t.Error("Permanent hides the error it wraps")
	}
}

func TestSupervisorRestartSkipsTheDelay(t *testing.T) {
	attempts := 0
	var reasons []string
	supervisor := &Supervisor{}
	supervisor.Prepare = func() (Login, config.Config, error) {
		attempts++
		if attempts < 3 {
			return Login{}, config.Config{}, fmt.Errorf("attempt %d failed", attempts)
		}
		return Login{}, config.Config{}, Permanent(errors.New("done"))
	}
	supervisor.OnReconnecting = func(reason string) {
		reasons = append(reasons, reason)
		supervisor.Restart()
	}

	start := time.Now()
	if err := supervisor.Run(context.Background()); err == nil || err.Error() != "done" {
		t.Fatalf("got %v, want done", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Run waited %s despite Restart", elapsed)
	}
	if want := []string{"attempt 1 failed", "attempt 2 failed"}; !slices.Equal(reasons, want) {
		t.Errorf("reconnecting reasons %q, want %q", reasons, want)
	}
}

func TestSupervisorEndsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	supervisor := &Supervisor{
		Prepare: func() (Login, config.Config, error) {
			cancel()
			return Login{}, config.Config{}, errors.New("interrupted")
		},
		OnReconnecting: func(string) { t.Error("reconnecting after ctx ended") },
	}
	if err := supervisor.Run(ctx); err != nil {
		t.Errorf("got %v, want nil", err)
	}
}
