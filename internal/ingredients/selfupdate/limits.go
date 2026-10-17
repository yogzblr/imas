package selfupdate

import (
	"time"

	"github.com/yogzblr/imas/internal/config"
)

// Bounds on a hostile update repository (security review 2026-10, I4).
// The repository is outside the sprout's trust: whatever it serves is
// only installed if its SHA-256 is on the signed checksums.txt line, but
// until that check it can still cost memory, disk and time, and an
// update holds the one update lock while it runs. Each bound comes from
// the sprout config (config.SproutUpdateMaxIndexBytes and the settings
// after it); a zero value, as in a process that never loaded the sprout
// config, is the config package's default.
type limits struct {
	// indexBytes caps each repository index, as downloaded and again
	// after decompression.
	indexBytes int64
	// packageBytes caps the package download (and the NuGet package
	// carrying an MSI); a size the repository's index declares for the
	// entry lowers it (declaredCap).
	packageBytes int64
	// request bounds one request to the repository, body included.
	request time.Duration
	// budget bounds the whole update up to the installer; when it runs
	// out the update fails and releases updateMu.
	budget time.Duration
}

// currentLimits returns the configured bounds, each within its hard
// ceiling.
func currentLimits() limits {
	l := limits{
		indexBytes:   config.SproutUpdateMaxIndexBytes,
		packageBytes: config.SproutUpdateMaxPackageBytes,
		request:      config.SproutUpdateRequestTimeout,
		budget:       config.SproutUpdateBudget,
	}
	if l.indexBytes <= 0 || l.indexBytes > config.MaxSproutUpdateMaxIndexBytes {
		l.indexBytes = config.DefaultSproutUpdateMaxIndexBytes
	}
	if l.packageBytes <= 0 || l.packageBytes > config.MaxSproutUpdateMaxPackageBytes {
		l.packageBytes = config.DefaultSproutUpdateMaxPackageBytes
	}
	if l.request <= 0 {
		l.request = config.DefaultSproutUpdateRequestTimeout
	}
	if l.budget <= 0 {
		l.budget = config.DefaultSproutUpdateBudget
	}
	return l
}

// declaredCap is the most a download may be: the package cap, lowered to
// the size the repository's index declares for the entry when it
// declares one (declared > 0).
func (l limits) declaredCap(declared int64) int64 {
	if declared > 0 && declared < l.packageBytes {
		return declared
	}
	return l.packageBytes
}
