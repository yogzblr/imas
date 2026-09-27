package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/busstatus"
)

func TestDescribeBusStatus(t *testing.T) {
	now := time.Date(2026, 9, 27, 10, 5, 0, 0, time.UTC)
	since := now.Add(-5 * time.Minute)
	const path = "/var/lib/imas/sprout/bus-status.json"
	alive := func(pid int) bool { return pid == 42 }
	for _, tc := range []struct {
		name    string
		st      busstatus.Status
		err     error
		want    busCheck
		wantSub []string
	}{
		{
			name:    "connected",
			st:      busstatus.Status{State: busstatus.Connected, Server: "tls://bus:443", Since: since, PID: 42},
			want:    busConnected,
			wantSub: []string{"connected to tls://bus:443", "(5m0s ago)"},
		},
		{
			name: "connected, recorded by a dead process",
			st:   busstatus.Status{State: busstatus.Connected, Server: "tls://bus:443", Since: since, PID: 7},
			want: busNotConnected,
			// Never "connected to": the state is stale.
			wantSub: []string{"unknown: connected was recorded by process 7"},
		},
		{
			name:    "lost connection",
			st:      busstatus.Status{State: busstatus.Disconnected, Server: "tls://bus:443", Since: since, PID: 42, Error: "EOF"},
			want:    busNotConnected,
			wantSub: []string{"disconnected since", ", from tls://bus:443: EOF; retrying"},
		},
		{
			name:    "never connected",
			st:      busstatus.Status{State: busstatus.Disconnected, Since: since, PID: 42, Error: "nats: authorization violation"},
			want:    busNotConnected,
			wantSub: []string{"disconnected since", "ago): nats: authorization violation; retrying"},
		},
		{
			name:    "starting",
			st:      busstatus.Status{State: busstatus.Starting, Since: since, PID: 42},
			want:    busNotConnected,
			wantSub: []string{"not connected yet", "enrolling"},
		},
		{
			name:    "stopped",
			st:      busstatus.Status{State: busstatus.Stopped, Since: since, PID: 42},
			want:    busNotConnected,
			wantSub: []string{"stopped since"},
		},
		{
			name:    "unknown state",
			st:      busstatus.Status{State: "sideways", Since: since, PID: 42},
			want:    busNotConnected,
			wantSub: []string{`unknown state "sideways"`},
		},
		{
			name:    "no file",
			err:     fmt.Errorf("open %s: %w", path, fs.ErrNotExist),
			want:    busNotRecorded,
			wantSub: []string{"nothing recorded in " + path},
		},
		{
			name:    "no access",
			err:     fmt.Errorf("open %s: %w", path, fs.ErrPermission),
			want:    busUnreadable,
			wantSub: []string{"run it elevated"},
		},
		{
			name:    "garbage",
			err:     errors.New("bus-status.json: invalid character"),
			want:    busUnreadable,
			wantSub: []string{"unknown: bus-status.json: invalid character"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text, check := describeBusStatus(tc.st, tc.err, path, alive, now)
			if check != tc.want {
				t.Errorf("check = %d, want %d (%s)", check, tc.want, text)
			}
			for _, sub := range tc.wantSub {
				if !strings.Contains(text, sub) {
					t.Errorf("text %q lacks %q", text, sub)
				}
			}
		})
	}
}

// The status file the recorder writes reads back as connected for this
// process: the writer and `imas-sprout status` agree on the format.
func TestDescribeBusStatusRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bus-status.json")
	r := busstatus.NewRecorder(path)
	r.Connected("tls://bus:443")
	st, err := busstatus.Read(path)
	self := func(pid int) bool { return pid == os.Getpid() }
	if text, check := describeBusStatus(st, err, path, self, time.Now()); check != busConnected {
		t.Errorf("check = %d (%s), want connected", check, text)
	}
}
