// Package selfupdate implements the sprout side of a fleet update
// (design doc §1.8, §2.3, §2.5, §2.6; requirement 20): the one-step job
// farmer sends for an internal.sprout.action self_update. The step
// carries one thing, the target version; everything else the sprout uses
// comes from a manifest fleetreleaser signed and from the sprout's own
// configuration. Its single method, apply:
//
//  1. checks the target against the running version: lower is refused
//     (no downgrades: allow_downgrade isn't in the signed manifest
//     format), equal is success with nothing to do;
//  2. GETs the manifest for its own OS/arch and the target version from
//     farmer's recipe endpoint (GET /v1/sprout/update-manifest), with its
//     gateway JWT, over a client that trusts only SproutRootCA;
//  3. verifies the manifest's Ed25519 signature against the keyring
//     shipped in the sprout package (config.SproutFleetSigningKeyring,
//     fleetsign.LoadKeyring), never a key fetched from farmer or the bus.
//     A missing or bad signature, or a key id the keyring doesn't hold, is
//     a refusal; there is no checksum-only fallback;
//  4. refuses a manifest whose signed min_sprout_version is above the
//     running version, and a file_name that isn't this platform's package
//     type (.deb, .rpm, .msi);
//  5. finds the package in the repository configured in the sprout
//     itself — the same apt, rpm or NuGet repository the Ansible role
//     imas_sprout installs from — by reading that repository's own index
//     for the entry with the signed SHA-256 (repo.go), and downloads it
//     over HTTPS verified against the OS trust store (not SproutRootCA),
//     through the environment's proxy, with the optional repo token and
//     without the sprout JWT;
//  6. checks the file's SHA-256 against the signed checksum (for an MSI,
//     the MSI inside the NuGet package) before anything else touches it;
//  7. reads the package's own metadata and requires it to name
//     imas-sprout at exactly the manifest's version (pkgmeta.go): a signed
//     checksum alone can name an older genuine package (security review
//     M1);
//  8. installs from that local file with the OS installer (dpkg -i,
//     rpm -U, zypper on SUSE, msiexec /i /qn on Windows) and restarts the
//     service onto the new version (install.go).
//
// FLAG FOR SECURITY REVIEW: this installs code as root/SYSTEM. Any tenant
// recipe can name this ingredient, but it can only ever install bytes
// whose SHA-256 a key in the shipped keyring signed, for a version farmer
// serves this sprout's tenant (that tenant approved it), from the
// repository the sprout's own administrator configured.
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
	// ErrBelowMinSproutVersion: the running version is below the signed
	// manifest's min_sprout_version.
	ErrBelowMinSproutVersion = errors.New("selfupdate: running version is below the release's min_sprout_version")
	// ErrNoManifest: farmer serves no manifest for this target and
	// platform.
	ErrNoManifest = errors.New("selfupdate: no update manifest")
	// ErrManifestMismatch: farmer served a manifest for a different
	// version, OS or arch than asked.
	ErrManifestMismatch = errors.New("selfupdate: manifest does not match the request")
	// ErrPackageTypeMismatch: the signed file_name isn't this platform's
	// package type.
	ErrPackageTypeMismatch = errors.New("selfupdate: manifest file_name is not this platform's package type")
	// ErrRepoNotConfigured: the update repository settings
	// (sproutupdaterepourl and friends) are unset or invalid.
	ErrRepoNotConfigured = errors.New("selfupdate: no valid update repository configured (sproutupdaterepourl)")
	// ErrChecksumMismatch: the downloaded file's SHA-256 isn't the signed
	// checksum_sha256.
	ErrChecksumMismatch = errors.New("selfupdate: package checksum does not match the signed checksum_sha256")
	// ErrUnsupportedPlatform: no installer for this OS, or the sprout
	// couldn't restart onto the new version here.
	ErrUnsupportedPlatform = errors.New("selfupdate: self-update not supported on this platform")
	// ErrInstallFailed: the OS installer failed.
	ErrInstallFailed = errors.New("selfupdate: install failed")
	// ErrUpdateInProgress: another self_update is running, or one has
	// installed and the service hasn't restarted onto it yet.
	ErrUpdateInProgress = errors.New("selfupdate: another update is in progress or awaiting restart")
)

var applyProps = ingredients.MethodPropsSet{
	{Key: fleetsign.PropVersion, Type: "string", IsReq: true, Description: "target sprout version (canonical semver, e.g. v2.4.1); the file, checksum and signature come from farmer's signed manifest"},
}

// stageDirName is the directory under config.CacheDir that holds
// downloads; it is emptied at the start of every update.
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
	manifest fleetsign.Manifest
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
	if err := pl.platform.preflight(); err != nil {
		return pl, err
	}
	if pl.repo, err = configuredRepo(pl.platform); err != nil {
		return pl, err
	}
	// The keyring is read before anything is fetched: without a trust
	// root there is nothing to verify against.
	keyring, err := fleetsign.LoadKeyring(config.SproutFleetSigningKeyring)
	if err != nil {
		return pl, fmt.Errorf("selfupdate: fleet signing keyring: %w", err)
	}
	if pl.manifest, err = fetchManifest(ctx, pl.platform, pl.target); err != nil {
		return pl, err
	}
	if err := keyring.Verify(pl.manifest); err != nil {
		return pl, fmt.Errorf("selfupdate: refusing %s: %w", pl.target, err)
	}
	// Signed, so these are fleetreleaser's values. ParseManifest already
	// refused min_sprout_version > version.
	if semver.Compare(pl.manifest.MinSproutVersion, pl.running) > 0 {
		return pl, fmt.Errorf("%w: %s needs at least %s, this sprout runs %s",
			ErrBelowMinSproutVersion, pl.target, pl.manifest.MinSproutVersion, pl.running)
	}
	if filepath.Ext(pl.manifest.FileName) != "."+pl.platform.pkgType {
		return pl, fmt.Errorf("%w: %s is not a .%s for %s", ErrPackageTypeMismatch, pl.manifest.FileName, pl.platform.pkgType, pl.platform)
	}
	return pl, nil
}

func (s SelfUpdate) apply(ctx context.Context) (cook.Result, error) {
	if !updateMu.TryLock() {
		return failed(ErrUpdateInProgress)
	}
	defer updateMu.Unlock()
	if installed.Load() {
		return failed(ErrUpdateInProgress)
	}

	pl, err := s.prepare(ctx)
	if err != nil {
		return failed(err)
	}
	if pl.upToDate {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.Snprintf("already running %s", pl.running)}}, nil
	}
	verified := cook.Snprintf("%s for %s: manifest signature verified against the keyring at %s; running %s, min_sprout_version %s",
		pl.target, pl.platform, config.SproutFleetSigningKeyring, pl.running, pl.manifest.MinSproutVersion)

	// A fresh, private directory per update: nothing left from an earlier
	// attempt, and nobody else can have placed a file in it.
	stageRoot := filepath.Join(config.CacheDir, stageDirName)
	if err := os.RemoveAll(stageRoot); err != nil {
		return failed(fmt.Errorf("selfupdate: clearing %s: %w", stageRoot, err), verified)
	}
	if err := os.MkdirAll(stageRoot, 0o700); err != nil {
		return failed(fmt.Errorf("selfupdate: creating %s: %w", stageRoot, err), verified)
	}
	stage, err := os.MkdirTemp(stageRoot, "update-")
	if err != nil {
		return failed(fmt.Errorf("selfupdate: creating a staging directory: %w", err), verified)
	}
	// The signed, validated file name: one plain path component.
	file := filepath.Join(stage, pl.manifest.FileName)

	from, err := pl.repo.fetchPackage(ctx, pl.manifest, stage, file)
	if err != nil {
		os.RemoveAll(stage)
		return failed(err, verified)
	}
	downloaded := cook.Snprintf("%s downloaded from %s; sha256 %s matches the signed manifest", pl.manifest.FileName, redact(from), pl.manifest.ChecksumSHA256)

	id, bound, err := verifyPackageIdentity(ctx, pl.platform, file, pl.manifest)
	if err != nil {
		os.RemoveAll(stage)
		return failed(err, verified, downloaded)
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
	pl, err := s.prepare(ctx)
	if err != nil {
		return failed(err)
	}
	if pl.upToDate {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.Snprintf("already running %s", pl.running)}}, nil
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("%s for %s: manifest signature verified; would fetch %s from the %s, check sha256 %s and that the package is %s at that version, and install it with %s (running %s)",
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
