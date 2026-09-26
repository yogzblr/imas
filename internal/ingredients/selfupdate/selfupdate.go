// Package selfupdate implements the sprout side of a fleet update
// (design doc §1.8, §2.2, §2.5): the one-step job farmer sends for an
// internal.sprout.action self_update. Its single method, apply:
//
//  1. verifies the release's Ed25519 signature over
//     version|artifact_url|checksum_sha256 against imas-fleet-signing's
//     current key versions, fetched live from farmer over the sprout's
//     SproutRootCA-pinned NATS connection (keys.go; the enrollment-time
//     pin is only a bootstrap fallback until the first live fetch
//     succeeds) — BEFORE any request to the artifact host. A missing
//     signature, an invalid one, or no usable key set is a refusal; there
//     is no checksum-only fallback;
//  2. downloads the artifact with internal/ingredients/file/http's
//     provider, trusting only config.SproutRootCA for the artifact host's
//     TLS certificate (the same root the sprout's farmer/NATS connection
//     pins), never the system CA pool;
//  3. checks the downloaded file's SHA-256 against checksum_sha256, as a
//     second, independent check;
//  4. hands the verified, staged binary to the install step.
//
// FLAG FOR SECURITY REVIEW. The install step itself — swapping the
// running binary with backup/restore-on-failure and restarting — is §2.3's
// rollout-safety work and is NOT implemented here: install defaults to
// refusing with ErrInstallNotImplemented, so a self_update job ends failed
// (with the artifact verified and staged) rather than claiming success a
// rollout gate would act on. Any tenant recipe can name this ingredient,
// but it can only ever act on a release CloudXP's fleetreleaser signed.
package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/ingredients"
	fhttp "github.com/yogzblr/imas/internal/ingredients/file/http"
)

var (
	ErrMethodUndefined = errors.New("selfupdate method undefined")
	ErrMissingProperty = errors.New("selfupdate: missing or non-string property")
	// ErrChecksumMismatch: the downloaded artifact's SHA-256 isn't the
	// signed checksum_sha256.
	ErrChecksumMismatch = errors.New("selfupdate: artifact checksum does not match the signed checksum_sha256")
	// ErrInstallNotImplemented: the artifact is verified and staged, but
	// installing it is §2.3's work, not this package's.
	ErrInstallNotImplemented = errors.New("selfupdate: installing a verified artifact is not implemented yet (design doc §2.3, yogzblr/imas#286)")
)

// install receives a staged artifact whose signature and checksum have
// both been verified. A seam for tests; see the package doc.
var (
	install = func(_ context.Context, _ fleetsign.Release, stagedPath string) error {
		return fmt.Errorf("%w; verified artifact left at %s", ErrInstallNotImplemented, stagedPath)
	}
)

var applyProps = ingredients.MethodPropsSet{
	{Key: fleetsign.PropVersion, Type: "string", IsReq: true, Description: "release version"},
	{Key: fleetsign.PropArtifactURL, Type: "string", IsReq: true, Description: "https URL of the release binary"},
	{Key: fleetsign.PropChecksumSHA256, Type: "string", IsReq: true, Description: "hex SHA-256 of the release binary"},
	{Key: fleetsign.PropSignature, Type: "string", IsReq: true, Description: "fleetreleaser's signature over version|artifact_url|checksum_sha256"},
}

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
	if _, _, err := parsed.release(); err != nil {
		return nil, err
	}
	return parsed, nil
}

// release reads the four string properties.
func (s SelfUpdate) release() (fleetsign.Release, string, error) {
	get := func(key string) (string, error) {
		v, ok := s.params[key].(string)
		if !ok {
			return "", fmt.Errorf("%w: %s", ErrMissingProperty, key)
		}
		return v, nil
	}
	var (
		rel fleetsign.Release
		sig string
		err error
	)
	if rel.Version, err = get(fleetsign.PropVersion); err != nil {
		return rel, "", err
	}
	if rel.ArtifactURL, err = get(fleetsign.PropArtifactURL); err != nil {
		return rel, "", err
	}
	if rel.ChecksumSHA256, err = get(fleetsign.PropChecksumSHA256); err != nil {
		return rel, "", err
	}
	// A missing signature property is read as "" so it reaches Verify and
	// is refused there as ErrMissingSignature, the same as an
	// un-migrated row's empty signature.
	sig, _ = s.params[fleetsign.PropSignature].(string)
	return rel, sig, nil
}

func failed(err error, notes ...fmt.Stringer) (cook.Result, error) {
	return cook.Result{Succeeded: false, Failed: true, Notes: notes}, err
}

// verify checks the release's signature against the trusted key set
// (keys.go). Its only network traffic is the key fetch from farmer; the
// artifact host is never contacted.
func (s SelfUpdate) verify(ctx context.Context) (fleetsign.Release, keySource, error) {
	rel, sig, err := s.release()
	if err != nil {
		return rel, "", err
	}
	src, err := verifyRelease(ctx, rel, sig)
	if err != nil {
		return rel, "", fmt.Errorf("selfupdate: refusing %s: %w", rel.Version, err)
	}
	return rel, src, nil
}

func (s SelfUpdate) apply(ctx context.Context) (cook.Result, error) {
	// 1. Signature first: nothing is fetched for a release that isn't
	// signed by a trusted key version.
	rel, src, err := s.verify(ctx)
	if err != nil {
		return failed(err)
	}

	// 2. Fetch, trusting only SproutRootCA.
	stageDir := filepath.Join(config.CacheDir, "selfupdate")
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		return failed(fmt.Errorf("selfupdate: creating %s: %w", stageDir, err))
	}
	// Named by the signed checksum: hex only, so no path from the release
	// fields reaches the filesystem.
	staged := filepath.Join(stageDir, "sprout-"+rel.ChecksumSHA256)
	provider, err := fhttp.HTTPFile{}.Parse(s.id, rel.ArtifactURL, staged, rel.ChecksumSHA256, map[string]interface{}{
		fhttp.PropRootCAFile: config.SproutRootCA,
		"hashType":           "sha256",
	})
	if err != nil {
		return failed(err)
	}
	if err := provider.Download(ctx); err != nil {
		os.Remove(staged)
		return failed(fmt.Errorf("selfupdate: downloading %s: %w", rel.Version, err))
	}

	// 3. Independent second check: the bytes are the signed checksum.
	ok, err := provider.Verify(ctx)
	if err != nil || !ok {
		os.Remove(staged)
		return failed(errors.Join(ErrChecksumMismatch, err))
	}
	if err := os.Chmod(staged, 0o700); err != nil {
		os.Remove(staged)
		return failed(err)
	}

	// 4. Install.
	verified := cook.Snprintf("%s: signature (against the %s) and sha256 verified, staged at %s", rel.Version, src, staged)
	if err := install(ctx, rel, staged); err != nil {
		return failed(err, verified)
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{verified, cook.Snprintf("%s installed", rel.Version)}}, nil
}

// Test is the dry run: it checks the signature against the pinned key
// (no network) and reports what apply would fetch.
func (s SelfUpdate) Test(ctx context.Context) (cook.Result, error) {
	if s.method != fleetsign.SelfUpdateMethod {
		return failed(errors.Join(ErrMethodUndefined, fmt.Errorf("method %s undefined", s.method)))
	}
	rel, src, err := s.verify(ctx)
	if err != nil {
		return failed(err)
	}
	return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
		cook.Snprintf("signature verified against the %s; would download %s from %s (trusting only %s) and check sha256 %s",
			src, rel.Version, rel.ArtifactURL, config.SproutRootCA, rel.ChecksumSHA256),
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
