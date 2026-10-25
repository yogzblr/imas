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
