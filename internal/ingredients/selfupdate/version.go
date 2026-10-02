package selfupdate

import (
	"fmt"
	"runtime/debug"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// runningVersion returns the running sprout's version as canonical
// semver ("v1.2.3", "v1.2.4-rc.1"). Both version refusals (downgrade and
// min_sprout_version) compare against it, so it fails closed: a build
// that doesn't know its own version can't self-update. A variable so
// tests can set it.
var runningVersion = buildInfoVersion

// buildInfoVersion reads the main module version the Go toolchain stamps
// into the binary from the VCS tag it was built at (Go 1.24+): "v0.2.0"
// for a release build at tag v0.2.0, the same tag goreleaser passes to
// cmd/sprout as main.Tag.
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
