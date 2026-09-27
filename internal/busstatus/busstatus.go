// Package busstatus records a sprout's bus connection state in a local
// file, so tools on the host (`imas-sprout status`, the imas_verify Ansible
// role, monitoring) can tell whether the sprout is connected without
// inferring it from the process's TCP sockets.
//
// The file (config.SproutBusStatusFile) is JSON, for example:
//
//	{"state":"connected","server":"tls://bus.example.com:443","since":"2026-09-27T10:00:00Z","pid":1234}
//
// It is replaced atomically on every change, so a reader sees either the
// old or the new state, never a partial one. A process that dies without
// shutting down leaves its last state behind: a reader must check that pid
// is the sprout process it expects (the service's main PID) before it
// trusts the state.
package busstatus

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/yogzblr/imas/internal/log"
)

// State is the sprout's bus connection state.
type State string

const (
	// Starting: the sprout is running but hasn't tried the bus yet
	// (loading the root CA, enrolling).
	Starting State = "starting"
	// Connected: connected to Server; nats.go has completed the CONNECT
	// handshake, so the server accepted the sprout's credentials.
	Connected State = "connected"
	// Disconnected: a connect attempt failed or the connection was lost,
	// and nats.go is retrying. Error says why, when known.
	Disconnected State = "disconnected"
	// Stopped: the sprout shut down cleanly.
	Stopped State = "stopped"
)

// Status is the content of the status file.
type Status struct {
	State State `json:"state"`
	// Server is the bus URL (credentials redacted) the sprout is connected
	// to, or, once disconnected, the one it last was connected to.
	Server string `json:"server,omitempty"`
	// Since is when the sprout entered State.
	Since time.Time `json:"since"`
	// PID is the sprout process that wrote the file.
	PID int `json:"pid"`
	// Error is why the sprout is disconnected, if known.
	Error string `json:"error,omitempty"`
}

// Read reads the status file at path. The error satisfies
// errors.Is(err, fs.ErrNotExist) if there is none.
func Read(path string) (Status, error) {
	var st Status
	data, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("%s: %w", path, err)
	}
	if st.State == "" {
		return st, fmt.Errorf("%s: no state", path)
	}
	return st, nil
}

// Write replaces the status file at path with st, atomically: through a
// temp file in the same directory and a rename. The directory is created
// if needed. The file holds no secrets and is world-readable, like the
// state directory, so an unprivileged `imas-sprout status` can read it.
func Write(path string, st Status) error {
	if path == "" {
		return errors.New("busstatus: no path configured")
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return renameRetry(tmpPath, path)
}

// renameRetry renames, retrying briefly: on Windows a reader that has the
// file open without FILE_SHARE_DELETE (Get-Content, for one) makes the
// rename fail until it closes it.
func renameRetry(from, to string) error {
	var err error
	for i := 0; i < renameAttempts; i++ {
		if err = os.Rename(from, to); err == nil {
			return nil
		}
		time.Sleep(renameRetryDelay)
	}
	return err
}

var (
	renameAttempts   = 10
	renameRetryDelay = 50 * time.Millisecond
)

// Recorder writes a sprout process's state transitions to its status
// file. Its methods are safe for concurrent use; nats.go calls the
// connection handlers that drive it on one goroutine, in order. Write
// errors are logged, not returned: the sprout keeps working without the
// file.
type Recorder struct {
	path string
	pid  int
	now  func() time.Time

	mu      sync.Mutex
	server  string // the last server connected to
	stopped bool
	lastErr string // the last write error logged
}

// NewRecorder returns a Recorder for this process that writes to path.
func NewRecorder(path string) *Recorder {
	return &Recorder{path: path, pid: os.Getpid(), now: time.Now}
}

// Starting records that the process is up but not yet connecting.
func (r *Recorder) Starting() { r.record(Starting, "", nil) }

// Connected records a connection (or reconnection) to server.
func (r *Recorder) Connected(server string) { r.record(Connected, server, nil) }

// Disconnected records a failed connect attempt or a lost connection;
// err may be nil.
func (r *Recorder) Disconnected(err error) { r.record(Disconnected, "", err) }

// Stopped records a clean shutdown. It is final: later calls, such as
// the disconnect nats.go reports while closing, are ignored.
func (r *Recorder) Stopped() { r.record(Stopped, "", nil) }

func (r *Recorder) record(state State, server string, cause error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	switch state {
	case Connected:
		r.server = server
	case Starting:
		r.server = ""
	case Stopped:
		r.stopped = true
	}
	st := Status{State: state, Server: r.server, Since: r.now().UTC(), PID: r.pid}
	if cause != nil {
		st.Error = cause.Error()
	}
	if err := Write(r.path, st); err != nil {
		// Once per distinct error, or a disconnected sprout with an
		// unwritable state directory logs this on every reconnect attempt.
		if msg := err.Error(); msg != r.lastErr {
			log.Warnf("cannot record the bus connection state in %s: %v", r.path, err)
			r.lastErr = msg
		}
		return
	}
	r.lastErr = ""
}
