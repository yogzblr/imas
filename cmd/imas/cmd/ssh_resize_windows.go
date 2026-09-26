//go:build windows

package cmd

import (
	nats "github.com/nats-io/nats.go"
)

// watchTerminalResize is not supported on Windows: there is no SIGWINCH
// equivalent, so terminal resize is not propagated to the sprout's PTY
// during a `imas ssh` session. This is a no-op rather than an error since
// resize handling is a convenience, not a required part of the session.
func watchTerminalResize(nc *nats.Conn, resizeSubject string, done <-chan struct{}) {}
