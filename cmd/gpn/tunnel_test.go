package main

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestRekeyInterval(t *testing.T) {
	tests := map[int]time.Duration{
		10800: 3*time.Hour - time.Minute,
		0:     0,
		60:    0,
		121:   61 * time.Second,
	}
	for timeout, want := range tests {
		if got := rekeyInterval(timeout); got != want {
			t.Errorf("rekeyInterval(%d) = %s, want %s", timeout, got, want)
		}
	}
}

func TestNeedsRebuild(t *testing.T) {
	if !needsRebuild(fmt.Errorf("%w: local address changed", errNetworkChanged)) || !needsRebuild(errRekeyDue) {
		t.Error("rekey and network change must rebuild at once")
	}
	if needsRebuild(errors.New("ESP tunnel dead")) || needsRebuild(nil) {
		t.Error("other failures must wait for the backoff")
	}
}
