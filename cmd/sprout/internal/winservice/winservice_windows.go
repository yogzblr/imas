//go:build windows

package winservice

import (
	"context"
	"time"

	"golang.org/x/sys/windows/svc"
)

// StopWaitHint is the StopPending wait hint: the sprout waits up to 10s
// for its NATS connection to close, plus margin.
const StopWaitHint = 15 * time.Second

// accepted are the controls the service takes while running.
const accepted = svc.AcceptStop | svc.AcceptShutdown

// IsService reports whether the process was started by the SCM.
func IsService() (bool, error) { return svc.IsWindowsService() }

// Run connects to the SCM as the service name and drives run with a
// Handler. It returns once the service has stopped.
func Run(name string, run func(context.Context)) error {
	return svc.Run(name, &Handler{Run: run})
}

// Handler is an svc.Handler that runs Run for the life of the service.
type Handler struct {
	// Run is the program's main loop. It must return once its context is
	// cancelled.
	Run func(context.Context)
}

// Execute reports StartPending, starts Run and reports Running. On Stop
// or Shutdown it reports StopPending, cancels Run's context and returns
// once Run has returned, which svc reports as Stopped with exit code 0.
// If Run returns by itself (a console signal cancelled it), Execute
// returns too. Change requests are served until then, so an Interrogate
// during the stop doesn't block the SCM's control dispatcher.
func (h *Handler) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Run(ctx)
	}()
	changes <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case <-done:
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				if ctx.Err() == nil {
					changes <- svc.Status{State: svc.StopPending, WaitHint: uint32(StopWaitHint / time.Millisecond)}
					cancel()
				}
			}
		}
	}
}
