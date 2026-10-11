// Package audit provides per-user audit logging for imas farmer actions.
//
// Every authenticated API action (cook, key accept, job cancel, prop changes,
// etc.) is recorded as one JSON line with the user's identity, timestamp,
// action type, and relevant targets.
//
// Records go to stdout, never to a file: farmer runs with a read-only root
// filesystem and no volume of its own. The log shipper (Fluent Bit) picks
// the lines up from the container's stdout, and audit is queried in the log
// platform, which keeps it for 30 days by default. Each line carries
// "kind":"audit", which tells it apart from the process's other logs.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Kind is the "kind" field of every audit line.
const Kind = "audit"

// Entry represents a single audit log record.
type Entry struct {
	Timestamp  time.Time       `json:"ts"`
	Username   string          `json:"username,omitempty"`
	Pubkey     string          `json:"pubkey"`
	RoleName   string          `json:"role"`
	Action     string          `json:"action"`
	Targets    []string        `json:"targets,omitempty"`
	Parameters json.RawMessage `json:"params,omitempty"`
	Success    bool            `json:"success"`
	Error      string          `json:"error,omitempty"`
}

// line is an Entry as written: Kind first, then the Entry's fields.
type line struct {
	Kind string `json:"kind"`
	Entry
}

// Logger writes audit entries as JSON lines to one writer.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

// NewLogger returns an audit logger that writes to w, or to stdout when w
// is nil.
func NewLogger(w io.Writer) *Logger {
	if w == nil {
		w = os.Stdout
	}
	return &Logger{w: w}
}

// Log writes entry as one JSON line. Lines are written whole: concurrent
// calls never interleave.
func (l *Logger) Log(entry Entry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(line{Kind: Kind, Entry: entry})
	if err != nil {
		return fmt.Errorf("audit: marshal entry: %w", err)
	}
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.w.Write(data); err != nil {
		return fmt.Errorf("audit: write entry: %w", err)
	}
	return nil
}
