//go:build !windows

package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

// watchTerminalResize delivers the terminal's new size on every SIGWINCH,
// until done is closed. The session sends each as a sealed RESIZE frame.
func watchTerminalResize(done <-chan struct{}) <-chan [2]int {
	sizes := make(chan [2]int, 1)
	sigWinch := make(chan os.Signal, 1)
	signal.Notify(sigWinch, syscall.SIGWINCH)
	go func() {
		defer signal.Stop(sigWinch)
		for {
			select {
			case <-sigWinch:
				if w, h, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
					select {
					case sizes <- [2]int{w, h}:
					default:
						// A newer size replaces one not yet sent.
						select {
						case <-sizes:
						default:
						}
						sizes <- [2]int{w, h}
					}
				}
			case <-done:
				return
			}
		}
	}()
	return sizes
}
