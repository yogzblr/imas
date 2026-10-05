package saasapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/objectstore"
)

// The recipe credential self-check (FIX.3; FLAG FOR SECURITY REVIEW).
//
// saasapi's recipe credential must reach only tenants/*/recipes/* (and
// PutObject on tenants/*/recipe-audit/*). The policy that limits it lives
// in the object store, where neither the chart nor saasapi can read it, so
// with SAASAPI_RECIPES_CREDENTIAL_CHECK=true saasapi asks the store at
// startup instead: it tries what the credential must NOT be able to do,
// and refuses to start if the store lets any of it through, or if it
// can't get an answer (fail closed). The probes:
//
//   - create an object outside tenants/ (at the bucket root);
//   - create an object under sprouts/ (farmer's staged recipes);
//   - read a key under sprouts/;
//   - list sprouts/.
//
// Writes are create-only at fresh random keys, so a probe never replaces
// anything, and an object a wrongly allowed probe created is deleted again
// before saasapi exits. The check proves the credential is no broader than
// those four requests show; it doesn't prove the whole policy. One known
// gap: AWS S3 answers a read of a missing key with AccessDenied, not
// NoSuchKey, to a caller without s3:ListBucket, so a credential allowed to
// read sprouts/* but not to list the bucket at all passes the read probe.
// The list probe still catches the common over-broad credential (farmer's
// own key, a bucket-wide or admin key).

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

// recipeCredentialProbes returns the self-check's probes, at keys made
// unique by nonce.
func recipeCredentialProbes(nonce string) []objectstore.Probe {
	return []objectstore.Probe{
		{Op: objectstore.ProbePut, Key: fmt.Sprintf("%s/%s", recipeCredentialCheckPrefix, nonce)},
		{Op: objectstore.ProbePut, Key: fmt.Sprintf("sprouts/%s/%s", recipeCredentialCheckPrefix, nonce)},
		{Op: objectstore.ProbeGet, Key: fmt.Sprintf("sprouts/%s/%s-read", recipeCredentialCheckPrefix, nonce)},
		{Op: objectstore.ProbeList, Key: "sprouts/"},
	}
}

// checkRecipeCredentialScope runs the self-check against store (saasapi's
// recipe store, opened with its own credential) and returns an error
// saying what to fix if the credential is broader than the recipe policy
// or the check couldn't tell.
func checkRecipeCredentialScope(ctx context.Context, store *objectstore.Store, bucket string) error {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("saasapi: recipe credential check: %w", err)
	}
	policy := recipeCredentialCheckPolicy
	policy.OnRetry = func(attempt int, wait time.Duration, err error) {
		log.Infof("saasapi: recipe credential check: object store not answering yet (attempt %d: %v), retrying in %s", attempt, err, wait)
	}
	err := store.ExpectDenied(ctx, recipeCredentialProbes(hex.EncodeToString(nonce[:])), policy)
	switch {
	case err == nil:
		log.Infof("saasapi: recipe credential check passed: bucket %s refuses this credential outside tenants/ and under sprouts/", bucket)
		return nil
	case errors.Is(err, objectstore.ErrAccessAllowed):
		return fmt.Errorf("saasapi: refusing to start: the recipe credential (SAASAPI_RECIPES_S3_ACCESS_KEY_ID) reaches beyond tenants/*/recipes/* in bucket %s; %v. "+
			"A compromised saasapi could rewrite farmer's staged recipes or platform recipes with it. "+
			"Give saasapi its own key limited by the policy in deploy/helm/farmer/files/objectstore-policies/saasapi-recipes.json, never farmer's key "+
			"(SAASAPI_RECIPES_CREDENTIAL_CHECK)", bucket, err)
	default:
		return fmt.Errorf("saasapi: refusing to start: could not verify the recipe credential's scope in bucket %s (SAASAPI_RECIPES_CREDENTIAL_CHECK): %w. "+
			"Check SAASAPI_RECIPES_S3_ENDPOINT, the bucket, the key pair and network access to the object store; "+
			"the check counts only AccessDenied as denied", bucket, err)
	}
}
