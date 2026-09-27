//go:build windows

package winservice

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

const testTimeout = 5 * time.Second

// exit is what Execute returned.
type exit struct {
	serviceSpecific bool
	code            uint32
}

// harness drives a Handler the way svc.Run does: a change-request channel
// in, a status channel out, Execute on its own goroutine.
type harness struct {
	t        *testing.T
	requests chan svc.ChangeRequest
	statuses chan svc.Status
	exited   chan exit
}

func start(t *testing.T, run func(context.Context)) *harness {
	t.Helper()
	h := &harness{
		t:        t,
		requests: make(chan svc.ChangeRequest),
		statuses: make(chan svc.Status),
		exited:   make(chan exit, 1),
	}
	go func() {
		ssec, code := (&Handler{Run: run}).Execute(nil, h.requests, h.statuses)
		h.exited <- exit{ssec, code}
	}()
	return h
}

func (h *harness) expect(want svc.Status) {
	h.t.Helper()
	select {
	case got := <-h.statuses:
		if got != want {
			h.t.Fatalf("status = %+v, want %+v", got, want)
		}
	case <-time.After(testTimeout):
		h.t.Fatalf("no status reported, want %+v", want)
	}
}

func (h *harness) send(c svc.ChangeRequest) {
	h.t.Helper()
	select {
	case h.requests <- c:
	case <-time.After(testTimeout):
		h.t.Fatalf("handler did not read change request %v", c.Cmd)
	}
}

func (h *harness) expectExit() {
	h.t.Helper()
	select {
	case e := <-h.exited:
		if e != (exit{}) {
			h.t.Fatalf("Execute returned (%v, %d), want (false, 0)", e.serviceSpecific, e.code)
		}
	case <-time.After(testTimeout):
		h.t.Fatal("Execute did not return")
	}
}

func (h *harness) expectNoExit() {
	h.t.Helper()
	select {
	case <-h.exited:
		h.t.Fatal("Execute returned before Run did")
	case <-time.After(50 * time.Millisecond):
	}
}

var (
	running     = svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	stopPending = svc.Status{State: svc.StopPending, WaitHint: 15000}
)

// blockingRun returns a Run that signals started, then waits for its
// context and for release before returning, like the sprout's wait for
// the NATS connection to close.
func blockingRun(started, cancelled, release chan struct{}) func(context.Context) {
	return func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-release
	}
}

func TestHandler_StopAndShutdown(t *testing.T) {
	for _, cmd := range []svc.Cmd{svc.Stop, svc.Shutdown} {
		t.Run(map[svc.Cmd]string{svc.Stop: "Stop", svc.Shutdown: "Shutdown"}[cmd], func(t *testing.T) {
			started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			h := start(t, blockingRun(started, cancelled, release))
			h.expect(svc.Status{State: svc.StartPending})
			h.expect(running)
			<-started

			h.send(svc.ChangeRequest{Cmd: cmd})
			h.expect(stopPending)
			select {
			case <-cancelled:
			case <-time.After(testTimeout):
				t.Fatal("Run's context was not cancelled")
			}
			// Execute waits for Run's shutdown.
			h.expectNoExit()
			close(release)
			h.expectExit()
		})
	}
}

func TestHandler_InterrogateWhileRunningAndStopping(t *testing.T) {
	started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h := start(t, blockingRun(started, cancelled, release))
	h.expect(svc.Status{State: svc.StartPending})
	h.expect(running)
	<-started

	h.send(svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: running})
	h.expect(running)

	h.send(svc.ChangeRequest{Cmd: svc.Stop})
	h.expect(stopPending)
	<-cancelled
	// Still served while Run shuts down, and a repeated Stop reports
	// nothing new.
	h.send(svc.ChangeRequest{Cmd: svc.Stop})
	h.send(svc.ChangeRequest{Cmd: svc.Interrogate, CurrentStatus: stopPending})
	h.expect(stopPending)
	close(release)
	h.expectExit()
}

func TestHandler_IgnoresUnacceptedControls(t *testing.T) {
	started, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h := start(t, blockingRun(started, cancelled, release))
	h.expect(svc.Status{State: svc.StartPending})
	h.expect(running)
	<-started

	h.send(svc.ChangeRequest{Cmd: svc.Pause})
	h.send(svc.ChangeRequest{Cmd: svc.ParamChange})
	select {
	case <-cancelled:
		t.Fatal("an unaccepted control cancelled Run")
	case s := <-h.statuses:
		t.Fatalf("unexpected status %+v", s)
	case <-time.After(50 * time.Millisecond):
	}

	h.send(svc.ChangeRequest{Cmd: svc.Stop})
	h.expect(stopPending)
	close(release)
	h.expectExit()
}

func TestHandler_RunReturnsByItself(t *testing.T) {
	ctxs := make(chan context.Context, 1)
	release := make(chan struct{})
	h := start(t, func(ctx context.Context) {
		ctxs <- ctx
		<-release
	})
	h.expect(svc.Status{State: svc.StartPending})
	h.expect(running)
	ctx := <-ctxs
	close(release)
	h.expectExit()
	if ctx.Err() == nil {
		t.Error("Run's context not cancelled after Execute returned")
	}
}
