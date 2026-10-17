// Package selfupdate implements the sprout side of a fleet update
// (design doc §1.8, §2.3, §2.5, §2.6; requirement 20): the one-step job
// farmer sends for an internal.sprout.action self_update. The step
// carries one thing, the target version; everything else the sprout uses
// comes from the release's GPG-signed checksums.txt, which farmer relays,
// and from the sprout's own configuration (P22, signing design D9, D20).
// Its single method, apply:
//
//  1. checks the target against the running version: lower is refused
//     (no downgrades), equal is success with nothing to do;
//  2. GETs the manifest for its own OS/arch and the target version from
//     farmer's recipe endpoint (GET /v1/sprout/update-manifest), with its
//     gateway JWT, over a client that trusts only SproutRootCA;
//  3. verifies the detached GPG signature over the exact checksums.txt
//     bytes against the keyring shipped in the sprout package
//     (config.SproutFleetSigningKeyring, fleetsign.LoadArmoredKeyring),
//     never a key fetched from farmer or the bus; parses checksums.txt
//     strictly; derives the package file name itself from the version,
//     OS, arch and package type (fleetsign.ExpectedFileName) and takes
//     the expected SHA-256 from that file's line. A missing or bad
//     signature, a malformed checksums.txt or no line for the file is a
//     refusal; there is no checksum-only fallback;
//  4. refuses a prerelease target on Windows (ErrPrereleaseOnWindows), a
//     manifest whose (unsigned, D19) min_sprout_version is above the
//     running version, and a manifest for another package type;
//  5. finds the package in the repository configured in the sprout
//     itself — the same apt, rpm or NuGet repository the Ansible role
//     imas_sprout installs from — by reading that repository's own index
//     for the entry with the signed SHA-256 (repo.go), and downloads it
//     over HTTPS verified against the OS trust store (not SproutRootCA),
//     through the environment's proxy, with the optional repo token and
//     without the sprout JWT;
//  6. checks the file's SHA-256 against the signed checksum (for an MSI,
//     the MSI inside the NuGet package) before anything else touches it,
//     having staged it in a fresh private directory (stageDir) and with
//     every read from the repository bounded (limits.go);
//  7. reads the package's own metadata and requires it to name
//     imas-sprout at exactly the target version (pkgmeta.go): a signed
//     checksum alone can name an older genuine package (security review
//     M1);
//  8. installs from that local file with the OS installer (dpkg -i,
//     rpm -U, zypper on SUSE, msiexec /i /qn on Windows) and restarts the
//     service onto the new version (install.go).
//
// FLAG FOR SECURITY REVIEW: this installs code as root/SYSTEM. Any tenant
// recipe can name this ingredient, but it can only ever install bytes
// whose SHA-256 is on the line for the sprout's own expected file name in
// a checksums.txt a key in the shipped keyring signed, for a version farmer
// serves this sprout's tenant (that tenant approved it), from the
// repository the sprout's own administrator configured. The keyring and
// the staging directories must be the sprout user's own and private
// (fleetsign.ErrUnsafePath, refusal code unsafe_path), and the update as
// a whole has a time budget (sproutupdatebudget) after which it fails and
// releases the update lock.
package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/mod/semver"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/ingredients"
)

var (
	ErrMethodUndefined = errors.New("selfupdate method undefined")
	ErrMissingProperty = errors.New("selfupdate: missing or non-string property")
	// ErrInvalidTargetVersion: the step's version isn't canonical semver.
	ErrInvalidTargetVersion = errors.New("selfupdate: target version is not a canonical semver version (vMAJOR.MINOR.PATCH[-PRERELEASE])")
	// ErrUnknownRunningVersion: the sprout can't tell which version it
	// runs, so it can't rule out a downgrade.
	ErrUnknownRunningVersion = errors.New("selfupdate: running version unknown")
	// ErrDowngrade: the target is lower than the running version.
	ErrDowngrade = errors.New("selfupdate: refusing to downgrade")
	// ErrBelowMinSproutVersion: the running version is below the
	// manifest's min_sprout_version.
	ErrBelowMinSproutVersion = errors.New("selfupdate: running version is below the release's min_sprout_version")
	// ErrNoManifest: farmer serves no manifest for this target and
	// platform.
	ErrNoManifest = errors.New("selfupdate: no update manifest")
	// ErrManifestMismatch: farmer served a manifest for a different
	// version, OS or arch than asked.
	ErrManifestMismatch = errors.New("selfupdate: manifest does not match the request")
	// ErrPackageTypeMismatch: the manifest's package_type isn't this
	// platform's.
	ErrPackageTypeMismatch = errors.New("selfupdate: manifest package_type is not this platform's package type")
	// ErrRepoNotConfigured: the update repository settings
	// (sproutupdaterepourl and friends) are unset or invalid.
	ErrRepoNotConfigured = errors.New("selfupdate: no valid update repository configured (sproutupdaterepourl)")
	// ErrChecksumMismatch: the downloaded file's SHA-256 isn't the one on
	// its line of the signed checksums.txt.
	ErrChecksumMismatch = errors.New("selfupdate: package checksum does not match the signed checksums.txt")
	// ErrUnsupportedPlatform: no installer for this OS, or the sprout
	// couldn't restart onto the new version here.
	ErrUnsupportedPlatform = errors.New("selfupdate: self-update not supported on this platform")
	// ErrInstallFailed: the OS installer failed.
	ErrInstallFailed = errors.New("selfupdate: install failed")
	// ErrPrereleaseOnWindows: the target is a prerelease and this sprout
	// installs an MSI. An MSI's ProductVersion has no prerelease part, so
	// the package can't be bound to the signed version (pkgmeta.go);
	// prerelease rollouts are refused on Windows (owner's decision,
	// 2026-10-04, PR #86).
	ErrPrereleaseOnWindows = errors.New("selfupdate: prerelease versions are not installed on Windows (an MSI ProductVersion can't carry the prerelease)")
	// ErrUpdateInProgress: another self_update is running, or one has
	// installed and the service hasn't restarted onto it yet.
	ErrUpdateInProgress = errors.New("selfupdate: another update is in progress or awaiting restart")
	// ErrBudgetExceeded: the update did not reach the installer within
	// its time budget (limits.budget, sproutupdatebudget).
	ErrBudgetExceeded = errors.New("selfupdate: the update ran out of its time budget (sproutupdatebudget)")
)

var applyProps = ingredients.MethodPropsSet{
	{Key: fleetsign.PropVersion, Type: "string", IsReq: true, Description: "target sprout version (canonical semver, e.g. v2.4.1); the checksum comes from the release's GPG-signed checksums.txt, which farmer relays"},
}

// stageDirName is the directory under config.CacheDir that holds
// downloads; it is removed and created again at the start of every
// update (stageDir).
const stageDirName = "selfupdate"

var (
	// updateMu admits one update at a time.
	updateMu sync.Mutex
	// installed is set once a package has been installed (or, on
	// Windows, scheduled): this process is about to be replaced, so it
	// refuses to start another update.
	installed atomic.Bool
)

// installedHold is how long installed refuses further updates.
const installedHold = 30 * time.Minute

// Compile-time interface check.
var _ cook.RecipeCooker = SelfUpdate{}

type SelfUpdate struct {
	id     string
	method string
	params map[string]interface{}
}

func (s SelfUpdate) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	parsed := SelfUpdate{id: id, method: method, params: params}
	if _, err := parsed.PropertiesForMethod(method); err != nil {
		return nil, err
	}
	if _, err := parsed.target(); err != nil {
		return nil, err
	}
	return parsed, nil
}

// target returns the step's target version. Farmer's dispatch sends only
// the version (internal/natsapi's sendSelfUpdate); any other property a
// tenant recipe sets is never read, since none of it is signed.
func (s SelfUpdate) target() (string, error) {
	v, ok := s.params[fleetsign.PropVersion].(string)
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrMissingProperty, fleetsign.PropVersion)
	}
	if len(v) > 64 || !semver.IsValid(v) || semver.Canonical(v) != v {
		return "", fmt.Errorf("%w: %q", ErrInvalidTargetVersion, v)
	}
	return v, nil
}

func failed(err error, notes ...fmt.Stringer) (cook.Result, error) {
	return cook.Result{Succeeded: false, Failed: true, Notes: notes}, err
}

// plan is a verified update, ready to download.
type plan struct {
	target, running string
	// upToDate: the target is the running version; nothing to do.
	upToDate bool
	platform platform
	repo     repo
	manifest release
}

// prepare runs every check that needs no download: steps 1–4 of the
// package doc, plus the platform preflight and the repository URL. Its
// only network traffic is the manifest request to farmer.
func (s SelfUpdate) prepare(ctx context.Context) (plan, error) {
	var pl plan
	var err error
	if pl.target, err = s.target(); err != nil {
		return pl, err
	}
	if pl.running, err = runningVersion(); err != nil {
		return pl, err
	}
	switch c := semver.Compare(pl.target, pl.running); {
	case c < 0:
		return pl, fmt.Errorf("%w: target %s is lower than the running %s", ErrDowngrade, pl.target, pl.running)
	case c == 0:
		pl.upToDate = true
		return pl, nil
	}
	if pl.platform, err = detectPlatform(); err != nil {
		return pl, err
	}
	if pl.platform.pkgType == pkgMSI && semver.Prerelease(pl.target) != "" {
		return pl, fmt.Errorf("%w: %s", ErrPrereleaseOnWindows, pl.target)
	}
	if err := pl.platform.preflight(); err != nil {
		return pl, err
	}
	if pl.repo, err = configuredRepo(pl.platform); err != nil {
		return pl, err
	}
	// The keyring is read before anything is fetched: without a trust
	// root there is nothing to verify against.
	keyring, err := fleetsign.LoadArmoredKeyring(config.SproutFleetSigningKeyring)
	if err != nil {
		return pl, fmt.Errorf("selfupdate: fleet signing keyring: %w", err)
	}
	m, err := fetchManifest(ctx, pl.platform, pl.target)
	if err != nil {
		return pl, err
	}
	if m.PackageType != pl.platform.pkgType {
		return pl, fmt.Errorf("%w: farmer sent a .%s release for %s", ErrPackageTypeMismatch, m.PackageType, pl.platform)
	}
	if pl.manifest, err = verifyRelease(keyring, m, pl.platform); err != nil {
		return pl, fmt.Errorf("selfupdate: refusing %s: %w", pl.target, err)
	}
	// Unsigned (D19): farmer policy, enforced here. ParseManifest already
	// refused min_sprout_version > version.
	if semver.Compare(pl.manifest.MinSproutVersion, pl.running) > 0 {
		return pl, fmt.Errorf("%w: %s needs at least %s, this sprout runs %s",
			ErrBelowMinSproutVersion, pl.target, pl.manifest.MinSproutVersion, pl.running)
	}
	return pl, nil
}

// verifyRelease is the P22 verification, in the wire contract's order:
// the signature over the exact checksums.txt bytes against keyring,
// checksums.txt parsed strictly, the file name derived here (never taken
// from farmer), and that file's line. m must be fetchManifest's result:
// the version, OS and arch the sprout asked for, its package type.
func verifyRelease(keyring fleetsign.ArmoredKeyring, m fleetsign.Manifest, p platform) (release, error) {
	txt := []byte(m.ChecksumsTxt)
	if err := keyring.VerifyChecksums(txt, m.Signature()); err != nil {
		return release{}, err
	}
	sums, err := fleetsign.ParseChecksums(txt)
	if err != nil {
		return release{}, err
	}
	name, err := fleetsign.ExpectedFileName(m.Version, p.os, p.arch, p.pkgType)
	if err != nil {
		return release{}, err
	}
	sum, ok := sums.Sum(name)
	if !ok {
		return release{}, fmt.Errorf("%w: %s", fleetsign.ErrNotInChecksums, name)
	}
	return release{Version: m.Version, FileName: name, ChecksumSHA256: sum, MinSproutVersion: m.MinSproutVersion}, nil
}

// withBudget returns ctx bounded by the update's time budget, and a func
// that turns an error into ErrBudgetExceeded once the budget has run out.
func withBudget(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc, func(error) error) {
	bctx, cancel := context.WithTimeout(ctx, budget)
	wrap := func(err error) error {
		if err != nil && !errors.Is(err, ErrBudgetExceeded) && errors.Is(bctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return fmt.Errorf("%w (%s): %w", ErrBudgetExceeded, budget, err)
		}
		return err
	}
	return bctx, cancel, wrap
}

// stageDir creates a fresh, private staging directory for one update
// (security review 2026-10, L3) and returns its path. The cache directory
// must be the sprout user's and not writable by others; the staging root
// below it is removed and made again (never reused, whoever owns what is
// there) and, like the per-update directory made in it, must be the
// sprout user's own, mode 0700, and not a symlink. Anything else is
// fleetsign.ErrUnsafePath, before anything is downloaded.
func stageDir() (string, error) {
	if err := os.MkdirAll(config.CacheDir, 0o700); err != nil {
		return "", fmt.Errorf("selfupdate: creating %s: %w", config.CacheDir, err)
	}
	if err := fleetsign.CheckNotWritableByOthers(config.CacheDir); err != nil {
		return "", fmt.Errorf("selfupdate: cache directory: %w", err)
	}
	stageRoot := filepath.Join(config.CacheDir, stageDirName)
	if err := os.RemoveAll(stageRoot); err != nil {
		return "", fmt.Errorf("selfupdate: clearing %s: %w", stageRoot, err)
	}
	// Mkdir, not MkdirAll: if anything appeared at stageRoot since it
	// was removed, refuse rather than use it.
	if err := os.Mkdir(stageRoot, 0o700); err != nil {
		return "", fmt.Errorf("selfupdate: creating %s: %w", stageRoot, err)
	}
	if err := fleetsign.CheckPrivateDir(stageRoot); err != nil {
		return "", fmt.Errorf("selfupdate: staging directory: %w", err)
	}
	stage, err := os.MkdirTemp(stageRoot, "update-")
	if err != nil {
		return "", fmt.Errorf("selfupdate: creating a staging directory: %w", err)
	}
	if err := checkStage(stage); err != nil {
		os.RemoveAll(stage)
		return "", err
	}
	return stage, nil
}

// checkStage checks the per-update staging directory and its parent, the
// staging root, again: right after they are made, and before the
// installer reads the package from them.
func checkStage(stage string) error {
	for _, dir := range []string{filepath.Dir(stage), stage} {
		if err := fleetsign.CheckPrivateDir(dir); err != nil {
			return fmt.Errorf("selfupdate: staging directory: %w", err)
		}
	}
	return nil
}

func (s SelfUpdate) apply(ctx context.Context) (cook.Result, error) {
	if !updateMu.TryLock() {
		return failed(ErrUpdateInProgress)
	}
	defer updateMu.Unlock()
	if installed.Load() {
		return failed(ErrUpdateInProgress)
	}

	// Everything up to the installer runs within the update's budget;
	// when it runs out, this returns and updateMu is released. The
	// installer has its own timeout (installTimeout) and is never cut
	// off part way by the budget.
	bctx, cancel, overBudget := withBudget(ctx, currentLimits().budget)
	defer cancel()

	pl, err := s.prepare(bctx)
	if err != nil {
		return failed(overBudget(err))
	}
	if pl.upToDate {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.Snprintf("already running %s", pl.running)}}, nil
	}
	verified := cook.Snprintf("%s for %s: checksums.txt signature verified against the keyring at %s; running %s, min_sprout_version %s",
		pl.target, pl.platform, config.SproutFleetSigningKeyring, pl.running, pl.manifest.MinSproutVersion)

	// A fresh, private directory per update: nothing left from an earlier
	// attempt, and nobody else can have placed a file in it.
	stage, err := stageDir()
	if err != nil {
		return failed(err, verified)
	}
	// The derived, validated file name: one plain path component.
	file := filepath.Join(stage, pl.manifest.FileName)

	from, err := pl.repo.fetchPackage(bctx, pl.manifest, stage, file)
	if err != nil {
		os.RemoveAll(stage)
		return failed(overBudget(err), verified)
	}
	downloaded := cook.Snprintf("%s downloaded from %s; sha256 %s matches the signed checksums.txt", pl.manifest.FileName, redact(from), pl.manifest.ChecksumSHA256)

	id, bound, err := verifyPackageIdentity(bctx, pl.platform, file, pl.manifest)
	if err == nil {
		err = checkStage(stage)
	}
	if err == nil && bctx.Err() != nil {
		err = overBudget(bctx.Err())
	}
	if err != nil {
		os.RemoveAll(stage)
		return failed(overBudget(err), verified, downloaded)
	}

	notes, err := installPackage(ctx, pl.platform, file, pl.target, filepath.Join(stage, "msiexec.log"), id)
	notes = append([]fmt.Stringer{verified, downloaded, bound}, notes...)
	if err != nil {
		os.RemoveAll(stage)
		return failed(err, notes...)
	}
	if pl.platform.installer != installMsiexec {
		// Installed; msiexec, on Windows, reads the file after this returns.
		os.RemoveAll(stage)
	}
	installed.Store(true)
	// If the restart never comes (systemctl failed, msiexec failed before
	// stopping the service), allow a retry eventually.
	time.AfterFunc(installedHold, func() { installed.Store(false) })
	return cook.Result{Succeeded: true, Changed: true, Notes: notes}, nil
}

// Test is the dry run: every check apply makes before downloading,
// including fetching and verifying the manifest, and what apply would
// fetch and install.
func (s SelfUpdate) Test(ctx context.Context) (cook.Result, error) {
	if s.method != fleetsign.SelfUpdateMethod {
		return failed(errors.Join(ErrMethodUndefined, fmt.Errorf("method %s undefined", s.method)))
	}
	bctx, cancel, overBudget := withBudget(ctx, currentLimits().budget)
	defer cancel()
	pl, err := s.prepare(bctx)
	if err != nil {
		return failed(overBudget(err))
	}
	if pl.upToDate {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.Snprintf("already running %s", pl.running)}}, nil
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("%s for %s: checksums.txt signature verified; would fetch %s from the %s, check sha256 %s and that the package is %s at that version, and install it with %s (running %s)",
			pl.target, pl.platform, pl.manifest.FileName, pl.repo, pl.manifest.ChecksumSHA256, sproutPackageName, pl.platform.installer, pl.running),
	}}, nil
}

func (s SelfUpdate) Apply(ctx context.Context) (cook.Result, error) {
	if s.method != fleetsign.SelfUpdateMethod {
		return failed(errors.Join(ErrMethodUndefined, fmt.Errorf("method %s undefined", s.method)))
	}
	return s.apply(ctx)
}

func (s SelfUpdate) PropertiesForMethod(method string) (map[string]string, error) {
	if method != fleetsign.SelfUpdateMethod {
		return nil, errors.Join(ErrMethodUndefined, fmt.Errorf("method %s undefined", method))
	}
	return applyProps.ToMap(), nil
}

func (s SelfUpdate) Methods() (string, []string) {
	return fleetsign.SelfUpdateIngredient, []string{fleetsign.SelfUpdateMethod}
}

func (s SelfUpdate) Properties() (map[string]interface{}, error) {
	m := map[string]interface{}{}
	b, err := json.Marshal(s.params)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(b, &m)
	return m, err
}

func init() {
	ingredients.RegisterAllMethods(SelfUpdate{})
}
