//go:build windows

package wintaskscheduler

import "github.com/yogzblr/imas/internal/ingredients"

// Registration and the COM backend are Windows-only; the rest of the
// package runs against the taskBackend interface, so its decisions are
// unit-tested on every platform.
func init() {
	backend = oleTaskBackend{}
	ingredients.RegisterAllMethods(Task{})
}
