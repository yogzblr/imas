package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPushAccountsUntilAccepted_RetriesUntilSuccess(t *testing.T) {
	var calls atomic.Int32
	push := func() (int, error) {
		if calls.Add(1) < 3 {
			return 0, errors.New("bus unreachable")
		}
		return 4, nil
	}
	done := make(chan struct{})
	go func() { pushAccountsUntilAccepted(context.Background(), push, time.Millisecond); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("did not stop after a successful push")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("push called %d times, want 3", got)
	}
}

func TestPushAccountsUntilAccepted_StopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	push := func() (int, error) { calls.Add(1); return 0, errors.New("bus unreachable") }
	done := make(chan struct{})
	go func() { pushAccountsUntilAccepted(ctx, push, time.Hour); close(done) }()
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("did not stop when its context was cancelled")
	}
}
