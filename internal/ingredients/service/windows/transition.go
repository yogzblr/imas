package windows

import "fmt"

// SERVICE_STATUS.dwCurrentState values (winsvc.h). Plain numbers, so the
// decision below has no build constraint and is tested on every platform.
const (
	stateStopped      uint32 = 1 // SERVICE_STOPPED
	stateStartPending uint32 = 2 // SERVICE_START_PENDING
	stateStopPending  uint32 = 3 // SERVICE_STOP_PENDING
	stateRunning      uint32 = 4 // SERVICE_RUNNING
)

// transitionFailed decides, while waiting for a service to reach want,
// whether the current state already says it never will: a service being
// started that is (back to) stopped has failed to start, and its exit
// codes say why. Before, the wait polled until the step's context ended,
// so a service that could not start held the step for as long as the
// caller allowed (with no deadline, for ever) and then reported only
// "context deadline exceeded".
//
// sawPending is whether the wait has seen the start in progress since it
// began: right after StartService the SCM can still report STOPPED for a
// moment, which is not yet a failure.
func transitionFailed(name string, want, state uint32, sawPending bool, win32Exit, specificExit uint32) error {
	if want != stateRunning || state != stateStopped || !sawPending {
		return nil
	}
	return fmt.Errorf("service %q stopped while starting: Win32 exit code %d, service-specific exit code %d", name, win32Exit, specificExit)
}

// stoppedPollsLimit is how many polls in a row a service being started may
// read STOPPED, without the start ever showing as pending, before the wait
// takes it as failed: a service that fails at once can go from
// START_PENDING back to STOPPED between two polls.
const stoppedPollsLimit = 10

// startWatch tracks a wait for want across polls: whether the start has
// shown as in progress, and how many polls in a row read STOPPED.
type startWatch struct {
	sawPending bool
	stopped    int
}

// observe records one polled state and says whether a STOPPED now counts
// as a failed start (transitionFailed's sawPending).
func (w *startWatch) observe(want, state uint32) bool {
	if want != stateRunning {
		return false
	}
	switch state {
	case stateStartPending:
		w.sawPending = true
		w.stopped = 0
	case stateStopped:
		w.stopped++
	default:
		w.stopped = 0
	}
	return w.sawPending || w.stopped >= stoppedPollsLimit
}
