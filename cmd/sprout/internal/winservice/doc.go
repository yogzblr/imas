// Package winservice runs the sprout's main loop under the Windows Service
// Control Manager (golang.org/x/sys/windows/svc). It is its own package,
// rather than part of cmd/sprout, so its tests don't run the sprout's
// init(), which writes the config and PKI directories.
package winservice
