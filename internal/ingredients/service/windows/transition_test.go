package windows

import (
	"strings"
	"testing"
)

func TestTransitionFailed(t *testing.T) {
	// A service that stops while it is being started (its process exited:
	// ERROR_SERVICE_SPECIFIC_ERROR 1066 with its own code 3) fails at once.
	err := transitionFailed("seclogon", stateRunning, stateStopped, true, 1066, 3)
	if err == nil || !strings.Contains(err.Error(), `service "seclogon" stopped while starting`) || !strings.Contains(err.Error(), "1066") {
		t.Fatalf("err = %v", err)
	}
	for _, tt := range []struct {
		want, state uint32
		sawPending  bool
	}{
		{stateRunning, stateStartPending, true}, // still starting
		{stateRunning, stateStopped, false},     // the start has not shown yet
		{stateStopped, stateStopPending, true},  // stopping
		{stateStopped, stateRunning, true},      // a stop not yet seen
	} {
		if err := transitionFailed("x", tt.want, tt.state, tt.sawPending, 0, 0); err != nil {
			t.Errorf("transitionFailed(want %d, state %d, pending %v) = %v, want nil", tt.want, tt.state, tt.sawPending, err)
		}
	}
}

// Right after StartService the SCM can still report STOPPED: that alone is
// not a failure, a STOPPED after START_PENDING is, and so is STOPPED on
// stoppedPollsLimit polls in a row (a start that failed between polls).
func TestStartWatch(t *testing.T) {
	var w startWatch
	if w.observe(stateRunning, stateStopped) {
		t.Fatal("a first STOPPED after StartService counted as a failed start")
	}
	w.observe(stateRunning, stateStartPending)
	if !w.observe(stateRunning, stateStopped) {
		t.Error("STOPPED after START_PENDING is a failed start")
	}
	var quick startWatch
	for i := 1; i < stoppedPollsLimit; i++ {
		if quick.observe(stateRunning, stateStopped) {
			t.Fatalf("failed after %d STOPPED polls", i)
		}
	}
	if !quick.observe(stateRunning, stateStopped) {
		t.Errorf("STOPPED on %d polls in a row is a failed start", stoppedPollsLimit)
	}
	var stop startWatch
	if stop.observe(stateStopped, stateStopped) {
		t.Error("a wait for STOPPED never fails on STOPPED")
	}
}
