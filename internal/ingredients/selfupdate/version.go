package selfupdate

import (
	"fmt"
	"runtime/debug"
	"sync/atomic"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// runningVersion returns the running sprout's version as canonical
// semver ("v1.2.3", "v1.2.4-rc.1"). Both version refusals (downgrade and
// min_sprout_version) compare against it, so it fails closed: a build
// that doesn't know its own version can't self-update. A variable so
// tests can set it.
var runningVersion = func() (string, error) {
	if tag := releaseTag.Load(); tag != nil && *tag != "" {
		return canonicalRunningVersion(*tag)
	}
	return buildInfoVersion()
}

// releaseTag is the tag cmd/sprout was linked with (SetRunningVersion).
var releaseTag atomic.Pointer[string]

// SetRunningVersion records the running sprout's release tag: cmd/sprout's
// main.Tag, which goreleaser links in as "v<version>" for every package
// build. It is the authoritative running version. Without it (a plain go
// build leaves main.Tag empty) the version the Go toolchain stamped from
// the VCS tag is used instead (buildInfoVersion).
func SetRunningVersion(tag string) {
	releaseTag.Store(&tag)
}

// buildInfoVersion reads the main module version the Go toolchain stamps
// into the binary from the VCS tag it was built at (Go 1.24+): "v0.2.0"
// for a build at tag v0.2.0. Only a fallback for builds without main.Tag.
//
// Anything else fails closed. A build outside a tagged checkout reports a
// pseudo-version (v0.0.0-<date>-<commit>), and so does a v2+ tag while the
// module path has no /v2 suffix; comparing against a pseudo-version would
// let a downgrade through, so it is refused instead.
func buildInfoVersion() (string, error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "", fmt.Errorf("%w: no build info in this binary", ErrUnknownRunningVersion)
	}
	return canonicalRunningVersion(bi.Main.Version)
}

// canonicalRunningVersion validates v as a release version and drops
// build metadata ("+dirty"), which semver ordering ignores anyway.
func canonicalRunningVersion(v string) (string, error) {
	c := semver.Canonical(v)
	if c == "" || !semver.IsValid(v) {
		return "", fmt.Errorf("%w: %q is not a semver version", ErrUnknownRunningVersion, v)
	}
	if module.IsPseudoVersion(v) {
		return "", fmt.Errorf("%w: %q is a pseudo-version, not a tagged release build", ErrUnknownRunningVersion, v)
	}
	return c, nil
}
