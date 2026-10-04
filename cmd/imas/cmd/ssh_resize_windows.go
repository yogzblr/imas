//go:build windows

package cmd

// watchTerminalResize is not supported on Windows: there is no SIGWINCH
// equivalent, so terminal resize is not propagated to the sprout's PTY
// during an `imas ssh` session. It returns nil (no resizes) rather than
// an error, since resize handling is a convenience.
func watchTerminalResize(done <-chan struct{}) <-chan [2]int { return nil }
