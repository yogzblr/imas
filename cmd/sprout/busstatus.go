package main

import (
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/yogzblr/imas/internal/busstatus"
)

// busCheck is what `imas-sprout status` makes of the bus status file.
type busCheck int

const (
	busConnected    busCheck = iota
	busNotConnected          // recorded, and not connected (or recorded by a dead process)
	busNotRecorded           // no status file
	busUnreadable            // the file can't be read or parsed
)

// describeBusStatus renders the result of busstatus.Read(path) for
// `imas-sprout status`. isSprout reports whether pid is the sprout process
// running now: a state recorded by any other process is stale.
func describeBusStatus(st busstatus.Status, readErr error, path string, isSprout func(pid int) bool, now time.Time) (string, busCheck) {
	switch {
	case errors.Is(readErr, fs.ErrNotExist):
		return fmt.Sprintf("unknown: nothing recorded in %s (the sprout hasn't started since it was installed or upgraded)", path),
			busNotRecorded
	case errors.Is(readErr, fs.ErrPermission):
		return fmt.Sprintf("unknown: %v (run it elevated, or as root, to see it)", readErr), busUnreadable
	case readErr != nil:
		return fmt.Sprintf("unknown: %v", readErr), busUnreadable
	case !isSprout(st.PID):
		return fmt.Sprintf("unknown: %s was recorded by process %d, which is no longer the running sprout", st.State, st.PID),
			busNotConnected
	}
	when := fmt.Sprintf("since %s (%s ago)", st.Since.Local().Format(time.RFC3339), now.Sub(st.Since).Round(time.Second))
	switch st.State {
	case busstatus.Connected:
		return fmt.Sprintf("connected to %s %s", st.Server, when), busConnected
	case busstatus.Disconnected:
		s := "disconnected " + when
		if st.Server != "" {
			s += ", from " + st.Server
		}
		if st.Error != "" {
			s += ": " + st.Error
		}
		return s + "; retrying", busNotConnected
	case busstatus.Starting:
		return "not connected yet: starting " + when + " (loading the root CA or enrolling)", busNotConnected
	case busstatus.Stopped:
		return "stopped " + when, busNotConnected
	}
	return fmt.Sprintf("unknown state %q %s", st.State, when), busNotConnected
}
