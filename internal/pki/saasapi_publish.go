package pki

// Publishing the SaaS API's minted NATS User JWT into OpenBao — the "JWT
// -> OpenBao hand-off" in docs/design/imas-internal-api-account.md. Run by
// `farmer publish-saasapi-credential` (cmd/farmer) as a Kubernetes Job,
// never by farmer's long-running server process: the store it writes to
// is backed by the one OpenBao identity allowed to write this secret.
//
// FLAG FOR SECURITY REVIEW: this is a new delivery path for a privileged
// NATS credential. Only the JWT (not secret on its own) and its public
// key are published; the seed never leaves the pod. The OpenBao policy
// boundary is documented in deploy/farmer/README.md.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	jwt "github.com/nats-io/jwt/v2"
)

// Field names in the published KV secret. An ExternalSecret maps
// SaaSAPICredentialJWTField onto the saasapi Deployment's
// SAASAPI_NATS_USER_JWT.
const (
	SaaSAPICredentialJWTField       = "jwt"
	SaaSAPICredentialPublicKeyField = "public_key"
)

// SaaSAPICredentialStore is the one secret PublishSaaSAPICredential reads
// and writes (an *openbaokv.Secret in production). Read returns (nil, nil)
// when the secret doesn't exist yet.
type SaaSAPICredentialStore interface {
	Read(ctx context.Context) (map[string]string, error)
	Write(ctx context.Context, data map[string]string) error
}

// ErrSaaSAPIKeyMaterialMissing means a key PublishSaaSAPICredential needs
// is not supplied: the NATS trust directory or the SAASAPI_USER seed.
// Farmer never generates the SaaS API's key: a key generated inside the
// Job's pod would be published for a JWT that nothing else holds,
// breaking the saasapi Deployment on its next restart.
var ErrSaaSAPIKeyMaterialMissing = errors.New("SaaS API credential key material is not available")

// PublishResult reports what PublishSaaSAPICredential did.
type PublishResult struct {
	// PublicKey is the SaaS API User's NKey public key the JWT is for.
	PublicKey string
	// Written is false when the store already held a JWT equivalent to
	// the current one (same key, issuer, permissions and connection
	// types), in which case nothing was written.
	Written bool
}

// requireSaaSAPIKeyMaterial checks that what the SaaS API User JWT
// depends on is supplied: the NATS trust directory (whose SYS account
// key, in Transit, signs it) and the SaaS API's own User key, from
// IMAS_NATS_SAASAPI_USER_SEED_FILE or _SEED.
func requireSaaSAPIKeyMaterial() error {
	dir := NATSTrustDir()
	if _, err := os.Stat(filepath.Join(dir, TrustSysAccountPub)); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: no NATS trust at %s (set %s to the mounted trust ConfigMap)",
				ErrSaaSAPIKeyMaterialMissing, dir, NATSTrustDirEnv)
		}
		return err
	}
	env := externalSeedEnvPrefix + saasAPIUserSeedName
	if os.Getenv(env+"_SEED_FILE") != "" || os.Getenv(env+"_SEED") != "" {
		return nil
	}
	return fmt.Errorf("%w: set %s_SEED_FILE", ErrSaaSAPIKeyMaterialMissing, env)
}

// PublishSaaSAPICredential runs EnsureSaaSAPICredential and hands the
// resulting User JWT to store, unless store already holds an equivalent
// one. Idempotent: re-running it when nothing changed reads the store and
// writes nothing.
//
// "Equivalent" is judged on the JWT's claims, not its bytes — the same
// check EnsureSaaSAPICredential uses to decide whether to re-mint. The
// Job keeps nothing between runs, so it mints a byte-different but
// equivalent JWT on every run; comparing bytes would
// write a new KV version, and restart saasapi via ESO/Reloader, every
// time.
//
// If EnsureSaaSAPICredential returns a valid credential together with an
// error (a failed resolver push of a key-rotation revocation), the
// credential is still published and that error is returned afterwards,
// so the Job reports failure and is retried without leaving saasapi on a
// stale JWT in the meantime.
func PublishSaaSAPICredential(ctx context.Context, store SaaSAPICredentialStore) (PublishResult, error) {
	if err := requireSaaSAPIKeyMaterial(); err != nil {
		return PublishResult{}, err
	}
	userJWT, _, ensureErr := EnsureSaaSAPICredential()
	if userJWT == "" {
		if ensureErr == nil {
			ensureErr = errors.New("EnsureSaaSAPICredential returned no JWT")
		}
		return PublishResult{}, ensureErr
	}
	uc, err := jwt.DecodeUserClaims(userJWT)
	if err != nil {
		return PublishResult{}, fmt.Errorf("decoding the minted SaaS API JWT: %w", err)
	}
	res := PublishResult{PublicKey: uc.Subject}

	existing, err := store.Read(ctx)
	if err != nil {
		return res, fmt.Errorf("reading the published SaaS API credential: %w", err)
	}
	if publishedSaaSAPICredentialIsCurrent(existing, uc.Subject, uc.Issuer) {
		return res, ensureErr
	}

	if err := store.Write(ctx, map[string]string{
		SaaSAPICredentialJWTField:       userJWT,
		SaaSAPICredentialPublicKeyField: uc.Subject,
	}); err != nil {
		return res, fmt.Errorf("publishing the SaaS API credential: %w", err)
	}
	res.Written = true
	return res, ensureErr
}

// publishedSaaSAPICredentialIsCurrent reports whether an already-published
// secret carries a JWT that verifies (DecodeUserClaims checks the
// signature against its issuer) and matches what would be minted now.
func publishedSaaSAPICredentialIsCurrent(existing map[string]string, pub, sysAccountPub string) bool {
	if existing == nil || existing[SaaSAPICredentialPublicKeyField] != pub {
		return false
	}
	uc, err := jwt.DecodeUserClaims(existing[SaaSAPICredentialJWTField])
	if err != nil {
		return false
	}
	return saasAPIUserJWTIsCurrent(uc, pub, sysAccountPub)
}
