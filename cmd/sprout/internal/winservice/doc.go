// Package winservice runs the sprout's main loop under the Windows Service
// Control Manager (golang.org/x/sys/windows/svc). It is its own package,
// rather than part of cmd/sprout, so its tests stay independent of the
// sprout's setup, which writes the config and PKI directories.
package winservice
