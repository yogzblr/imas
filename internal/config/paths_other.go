//go:build !windows

package config

// Default locations for the farmer/sprout config root and the sprout's
// local state. See paths_windows.go for the Windows equivalents.

func defaultSystemConfigRoot() string { return "/etc/imas" }

func defaultSproutCacheDir() string { return "/var/cache/imas/sprout/files/provided" }

func defaultSproutJobLogDir() string { return "/var/cache/imas/sprout/jobs" }

func defaultSproutHandledJobsFile() string { return "/var/lib/imas/sprout/handled-jobs" }

// SproutBusStatusFile is where the sprout records its bus connection state
// (internal/busstatus). It isn't a config setting, so readers
// (`imas-sprout status`, the imas_verify Ansible role, monitoring) find it
// without parsing the sprout's config file.
func SproutBusStatusFile() string { return "/var/lib/imas/sprout/bus-status.json" }

// SecureSproutConfigRoot is a no-op outside Windows: the packages create
// /etc/imas and the sprout tightens its config file's mode itself (see
// sproutConfigMode).
func SecureSproutConfigRoot() error { return nil }
