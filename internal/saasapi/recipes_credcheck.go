package saasapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/objectstore"
)

// The recipe credential self-check (FIX.3, extended in FIX.5; FLAG FOR
// SECURITY REVIEW).
//
// saasapi's recipe credential must reach only tenants/*/recipes/* (and
// PutObject on tenants/*/recipe-audit/*) in the recipe bucket, and nothing
// in farmer's job bucket. The policy that limits it lives in the object
// store, where neither the chart nor saasapi can read it, so with
// SAASAPI_RECIPES_CREDENTIAL_CHECK=true saasapi asks the store at startup
// instead: it tries what the credential must NOT be able to do, and
// refuses to start if the store lets any of it through, or if it can't
// get an answer (fail closed). The probes, in the recipe bucket:
//
//   - create an object outside tenants/ (at the bucket root);
//   - create an object under sprouts/ (farmer's staged recipes);
//   - read a key under sprouts/;
//   - list sprouts/;
//   - create an object under the platform recipe prefix (FIX.5);
//   - delete a key under the platform recipe prefix (FIX.5);
//
// and in the job bucket (FIX.5), where any access must be refused
// (SAASAPI_RECIPES_JOB_BUCKET, required while the check is on):
//
//   - create an object under jobs/;
//   - read a key under jobs/;
//   - delete a key under jobs/;
//   - list jobs/, and list the whole bucket.
//
// Writes are create-only at fresh random keys, so a probe never replaces
// anything, and an object a wrongly allowed probe created is deleted again
// before saasapi exits. Deletes are of fresh random keys nothing wrote, so
// a wrongly allowed one removes nothing (a versioned bucket gets a delete
// marker at that key). The check proves the credential is no broader than
// those requests show; it doesn't prove the whole policy. One known gap:
// AWS S3 answers a read of a missing key with AccessDenied, not NoSuchKey,
// to a caller without s3:ListBucket, so a credential allowed to read
// sprouts/* (or job bucket keys) but not to list that bucket at all passes
// the read probe. The list probes still catch the common over-broad
// credential (farmer's own key, a bucket-wide or admin key). Closing the
// gap needs a key known to exist in each place, which saasapi can't create
// with a credential that is correctly limited.

// recipeCredentialCheckPolicy bounds the self-check's retries while the
// store can't be reached: about half a minute in all, inside saasapi's
// liveness window (its probe starts once the listener is up, after this).
// A variable so tests can shorten it.
var recipeCredentialCheckPolicy = objectstore.RetryPolicy{
	MaxAttempts:    6,
	InitialBackoff: time.Second,
	MaxBackoff:     8 * time.Second,
	AttemptTimeout: 5 * time.Second,
}

// recipeCredentialCheckPrefix names the probe objects, so one left behind
// (when deleting it failed too) is recognisable.
const recipeCredentialCheckPrefix = "imas-saasapi-credential-check"

// sproutsPrefix is farmer's staged recipe tree in the recipe bucket
// (internal/cook stagedRecipeRoot), which the credential must not reach.
const sproutsPrefix = "sprouts/"

// jobsPrefix is the job bucket's key root (internal/jobs).
const jobsPrefix = "jobs/"

// recipeCredentialProbes returns the self-check's probes in the recipe
// bucket, at keys made unique by nonce. platformPrefix is the platform
// recipe prefix, as cook.PlatformRecipePrefix returns it.
func recipeCredentialProbes(nonce, platformPrefix string) []objectstore.Probe {
	return []objectstore.Probe{
		{Op: objectstore.ProbePut, Key: fmt.Sprintf("%s/%s", recipeCredentialCheckPrefix, nonce)},
		{Op: objectstore.ProbePut, Key: fmt.Sprintf("sprouts/%s/%s", recipeCredentialCheckPrefix, nonce)},
		{Op: objectstore.ProbeGet, Key: fmt.Sprintf("sprouts/%s/%s-read", recipeCredentialCheckPrefix, nonce)},
		{Op: objectstore.ProbeList, Key: sproutsPrefix},
		{Op: objectstore.ProbePut, Key: fmt.Sprintf("%s%s/%s", platformPrefix, recipeCredentialCheckPrefix, nonce)},
		{Op: objectstore.ProbeDelete, Key: fmt.Sprintf("%s%s/%s-delete", platformPrefix, recipeCredentialCheckPrefix, nonce)},
	}
}

// jobBucketCredentialProbes returns the self-check's probes in the job
// bucket: every kind of access, all of which must be refused.
func jobBucketCredentialProbes(nonce string) []objectstore.Probe {
	return []objectstore.Probe{
		{Op: objectstore.ProbePut, Key: fmt.Sprintf("%s%s/%s", jobsPrefix, recipeCredentialCheckPrefix, nonce)},
		{Op: objectstore.ProbeGet, Key: fmt.Sprintf("%s%s/%s-read", jobsPrefix, recipeCredentialCheckPrefix, nonce)},
		{Op: objectstore.ProbeDelete, Key: fmt.Sprintf("%s%s/%s-delete", jobsPrefix, recipeCredentialCheckPrefix, nonce)},
		{Op: objectstore.ProbeList, Key: jobsPrefix},
		{Op: objectstore.ProbeList, Key: ""},
	}
}

// recipeCredentialScope is what the self-check probes: the recipe bucket
// (saasapi's recipe store, opened with its own credential) with farmer's
// platform recipe prefix in it, and farmer's job bucket opened with the
// same credential.
type recipeCredentialScope struct {
	recipes        *objectstore.Store
	recipeBucket   string
	platformPrefix string
	jobs           *objectstore.Store
	jobBucket      string
}

// checkRecipeCredentialScope runs the self-check and returns an error
// saying what to fix if the credential is broader than the recipe policy
// or the check couldn't tell. Every probe is made, in both buckets, before
// it decides; a missing recipe store, platform prefix or job store fails
// it (fail closed).
func checkRecipeCredentialScope(ctx context.Context, sc recipeCredentialScope) error {
	if sc.recipes == nil || sc.platformPrefix == "" || sc.jobs == nil {
		return errors.New("saasapi: refusing to start: the recipe credential check needs the recipe bucket, the platform recipe prefix and the job bucket (SAASAPI_RECIPES_CREDENTIAL_CHECK, SAASAPI_RECIPES_JOB_BUCKET)")
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("saasapi: recipe credential check: %w", err)
	}
	n := hex.EncodeToString(nonce[:])
	policy := recipeCredentialCheckPolicy
	policy.OnRetry = func(attempt int, wait time.Duration, err error) {
		log.Infof("saasapi: recipe credential check: object store not answering yet (attempt %d: %v), retrying in %s", attempt, err, wait)
	}
	recipeErr := sc.recipes.ExpectDenied(ctx, recipeCredentialProbes(n, sc.platformPrefix), policy)
	jobErr := sc.jobs.ExpectDenied(ctx, jobBucketCredentialProbes(n), policy)

	var allowed, inconclusive errList
	for _, r := range []struct {
		err  error
		what string
	}{{recipeErr, "recipe bucket " + sc.recipeBucket}, {jobErr, "job bucket " + sc.jobBucket}} {
		switch {
		case errors.Is(r.err, objectstore.ErrAccessAllowed):
			allowed = append(allowed, fmt.Errorf("in %s: %w", r.what, r.err))
		case r.err != nil:
			inconclusive = append(inconclusive, fmt.Errorf("in %s: %w", r.what, r.err))
		}
	}
	if len(allowed) > 0 {
		return fmt.Errorf("saasapi: refusing to start: the recipe credential (SAASAPI_RECIPES_S3_ACCESS_KEY_ID) reaches beyond tenants/*/recipes/* in bucket %s; %w. "+
			"A compromised saasapi could rewrite farmer's staged recipes or platform recipes (prefix %s), or read or rewrite job logs, with it. "+
			"Give saasapi its own key limited by the policy in deploy/helm/farmer/files/objectstore-policies/saasapi-recipes.json, never farmer's key "+
			"(SAASAPI_RECIPES_CREDENTIAL_CHECK)", sc.recipeBucket, allowed, sc.platformPrefix)
	}
	if len(inconclusive) > 0 {
		return fmt.Errorf("saasapi: refusing to start: could not verify the recipe credential's scope in buckets %s and %s (SAASAPI_RECIPES_CREDENTIAL_CHECK): %w. "+
			"Check SAASAPI_RECIPES_S3_ENDPOINT, both buckets (SAASAPI_RECIPES_S3_BUCKET, SAASAPI_RECIPES_JOB_BUCKET), the key pair and network access to the object store; "+
			"the check counts only AccessDenied as denied", sc.recipeBucket, sc.jobBucket, inconclusive)
	}
	log.Infof("saasapi: recipe credential check passed: bucket %s refuses this credential outside tenants/, under sprouts/ and under the platform recipe prefix %s, and job bucket %s refuses it everything",
		sc.recipeBucket, sc.platformPrefix, sc.jobBucket)
	return nil
}

// errList is several errors as one, on one line, matching (errors.Is) any
// of them.
type errList []error

func (l errList) Error() string {
	msgs := make([]string, len(l))
	for i, err := range l {
		msgs[i] = err.Error()
	}
	return strings.Join(msgs, "; ")
}

func (l errList) Unwrap() []error { return l }
