package relay

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSendReachesWaitingListener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "callback.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	if _, err := Listen(path); err == nil {
		t.Error("second Listen succeeded, want error")
	}

	const uri = "globalprotectcallback:cas-as=1&un=alice&token=t"
	go Send(path, uri)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := listener.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != uri {
		t.Errorf("Wait() = %q, want %q", got, uri)
	}
}

func TestSendWithoutListener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "callback.sock")
	if err := Send(path, "globalprotectcallback:x"); !errors.Is(err, ErrNoListener) {
		t.Errorf("Send() = %v, want ErrNoListener", err)
	}
}
