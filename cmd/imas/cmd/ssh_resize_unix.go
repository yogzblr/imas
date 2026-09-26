//go:build !windows

package cmd

import (
	"encoding/json"
	"os"
	"os/signal"
	"syscall"

	nats "github.com/nats-io/nats.go"
	"golang.org/x/term"

	"github.com/yogzblr/imas/internal/shell"
)

// watchTerminalResize watches for SIGWINCH (terminal resize) and publishes
// a shell.ResizeMessage to resizeSubject whenever the terminal size
// changes, until done is closed.
func watchTerminalResize(nc *nats.Conn, resizeSubject string, done <-chan struct{}) {
	sigWinch := make(chan os.Signal, 1)
	signal.Notify(sigWinch, syscall.SIGWINCH)
	go func() {
		for {
			select {
			case <-sigWinch:
				if w, h, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
					resize := shell.ResizeMessage{Cols: w, Rows: h}
					data, _ := json.Marshal(resize)
					nc.Publish(resizeSubject, data)
				}
			case <-done:
				return
			}
		}
	}()
}
