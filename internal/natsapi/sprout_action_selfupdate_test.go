package natsapi

// self_update on internal.sprout.action (design doc §1.8, §2.3, §2.5;
// FLAG FOR SECURITY REVIEW): the request names only a version, and farmer
// re-verifies it against the release catalog it reads read-only
// (internal/fleetcatalog) before anything reaches a sprout: the version
// must be the sprout's tenant's approved_version, registered, not revoked,
// and every row of it must verify against the imas-fleet-signing key.
// Refusals are invalid_request; nothing is dispatched.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/fleetcatalog"
	"github.com/yogzblr/imas/internal/fleetcatalog/fleetcatalogtest"
	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

const (
	suVersion = "v2.4.1"
	suTenant  = "t_1"
)

type staticKeys struct {
	ks  fleetsign.KeySet
	err error
}

func (s staticKeys) KeySet(context.Context) (fleetsign.KeySet, error) { return s.ks, s.err }

func ptr(s string) *string { return &s }

// suCatalog is a real fleetcatalog.SQL over a SQLite saas schema, with
// suVersion registered as a deb, an rpm and an MSI, all signed by priv,
// and suTenant approving it. It is installed for the test, with a key
// source holding priv's public key.
type suCatalog struct {
	t    *testing.T
	db   *gorm.DB
	priv ed25519.PrivateKey
}

func newSUCatalog(t *testing.T) (*suCatalog, func(fleetcatalog.Row), func(tenant string, version *string)) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := fleetsign.NewKeySet([]fleetsign.PublicKey{{Version: 1, Key: pub}})
	db := fleetcatalogtest.Open(t)
	origCat, origKeys := fleetcatalog.Current(), fleetKeys
	fleetcatalog.Install(fleetcatalog.New(db))
	SetFleetKeySource(staticKeys{ks: ks})
	enableSelfUpdate(t)
	t.Cleanup(func() { fleetcatalog.Install(origCat); SetFleetKeySource(origKeys) })

	c := &suCatalog{t: t, db: db, priv: priv}
	add := func(r fleetcatalog.Row) { fleetcatalogtest.AddRow(t, db, r) }
	approve := func(tenant string, version *string) { fleetcatalogtest.Approve(t, db, tenant, version) }
	for _, p := range [][3]string{{"linux", "amd64", "deb"}, {"linux", "amd64", "rpm"}, {"windows", "amd64", "msi"}} {
		add(c.row(suVersion, p[0], p[1], p[2]))
	}
	approve(suTenant, ptr(suVersion))
	return c, add, approve
}

func (c *suCatalog) row(version, os, arch, pkg string) fleetcatalog.Row {
	return fleetcatalogtest.Signed(c.t, c.priv, version, os, arch, pkg)
}

func suRequest(t *testing.T, tenantID, sproutID string, params any) []byte {
	t.Helper()
	return mustJSON(t, controlplane.SproutActionRequest{
		TenantID: tenantID, SproutID: sproutID,
		Action: controlplane.SproutAction{Type: controlplane.ActionSelfUpdate, Params: mustJSON(t, params)},
	})
}

func assertRefused(t *testing.T, reply controlplane.SproutActionReply, rec *dispatchRecorder, want controlplane.ErrorCode) {
	t.Helper()
	if reply.Status != controlplane.StatusFailed || reply.ErrorCode != want || reply.JID != "" {
		t.Fatalf("reply = %+v, want failed/%s", reply, want)
	}
	if calls := rec.all(); len(calls) != 0 {
		t.Fatalf("a refused self_update was dispatched: %+v", calls)
	}
}

// TestSelfUpdate_ApprovedSignedVersionDispatches: the happy path, and the
// dispatch is told only the version.
func TestSelfUpdate_ApprovedSignedVersionDispatches(t *testing.T) {
	rec := stubSproutActionDispatch(t, func(string, string) error { return nil })
	newSUCatalog(t)

	reply := handleSproutAction(suRequest(t, suTenant, "web-01", controlplane.SelfUpdateParams{Version: suVersion}))
	if reply.Status != controlplane.StatusDispatched || reply.JID != "jid-su" || reply.ErrorCode != "" {
		t.Fatalf("reply = %+v", reply)
	}
	calls := rec.all()
	if len(calls) != 1 || calls[0].tenantID != suTenant || string(calls[0].params) != `{"version":"v2.4.1"}` {
		t.Fatalf("dispatched %+v", calls)
	}
}

// TestSelfUpdate_ExtraFieldsRejected: a caller still sending the pre-FU.7
// params (artifact URL, checksum, signature), or anything else besides
// the version, gets invalid_request, even for an approved, signed version.
func TestSelfUpdate_ExtraFieldsRejected(t *testing.T) {
	newSUCatalog(t)
	for name, params := range map[string]any{
		"pre-FU.7 params": map[string]string{"version": suVersion, "artifact_url": "https://a.example.com/x",
			"checksum_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "signature": "v1:AAAA"},
		"empty legacy fields":  map[string]string{"version": suVersion, "artifact_url": "", "checksum_sha256": "", "signature": ""},
		"unknown field":        map[string]any{"version": suVersion, "os": "linux"},
		"version not a string": map[string]any{"version": 241},
		"not an object":        []string{suVersion},
	} {
		t.Run(name, func(t *testing.T) {
			rec := stubSproutActionDispatch(t, func(string, string) error { return nil })
			assertRefused(t, handleSproutAction(suRequest(t, suTenant, "web-01", params)), rec, controlplane.ErrorInvalidRequest)
		})
	}
}

// TestSelfUpdate_RefusedBeforeDispatch: every catalog refusal, and every
// failure to read the catalog or keys. Each fails before dispatch.
func TestSelfUpdate_RefusedBeforeDispatch(t *testing.T) {
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherKeys, _ := fleetsign.NewKeySet([]fleetsign.PublicKey{{Version: 1, Key: otherPub}})

	cases := []struct {
		name    string
		tenant  string // default suTenant
		version string
		setup   func(c *suCatalog, add func(fleetcatalog.Row), approve func(string, *string))
		want    controlplane.ErrorCode
	}{
		{name: "not canonical semver", version: "2.4.1", want: controlplane.ErrorInvalidRequest},
		{name: "build metadata", version: "v2.4.1+x", want: controlplane.ErrorInvalidRequest},
		{name: "unregistered (approved, but no rows)", tenant: "t_unreg", version: "v2.9.0", want: controlplane.ErrorInvalidRequest,
			setup: func(_ *suCatalog, _ func(fleetcatalog.Row), approve func(string, *string)) {
				approve("t_unreg", ptr("v2.9.0"))
			}},
		{name: "revoked", version: suVersion, want: controlplane.ErrorInvalidRequest,
			setup: func(c *suCatalog, _ func(fleetcatalog.Row), _ func(string, *string)) {
				fleetcatalogtest.Revoke(c.t, c.db, suVersion)
			}},
		{name: "tenant with no approved version", tenant: "t_null", version: suVersion, want: controlplane.ErrorInvalidRequest,
			setup: func(_ *suCatalog, _ func(fleetcatalog.Row), approve func(string, *string)) {
				approve("t_null", nil)
			}},
		{name: "tenant with no policy row", tenant: "t_nopolicy", version: suVersion, want: controlplane.ErrorInvalidRequest},
		{name: "registered but not the approved version", version: "v2.5.0", want: controlplane.ErrorInvalidRequest,
			setup: func(c *suCatalog, add func(fleetcatalog.Row), _ func(string, *string)) {
				add(c.row("v2.5.0", "linux", "amd64", "deb"))
			}},
		{name: "one row among several signed by an untrusted key", version: suVersion, want: controlplane.ErrorInvalidRequest,
			setup: func(c *suCatalog, add func(fleetcatalog.Row), _ func(string, *string)) {
				add(fleetcatalogtest.Signed(c.t, otherPriv, suVersion, "linux", "arm64", "deb"))
			}},
		{name: "one row among several tampered after signing", version: suVersion, want: controlplane.ErrorInvalidRequest,
			setup: func(c *suCatalog, add func(fleetcatalog.Row), _ func(string, *string)) {
				r := c.row(suVersion, "linux", "arm64", "rpm")
				r.Manifest.ChecksumSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
				add(r)
			}},
		{name: "one row among several unsigned", version: suVersion, want: controlplane.ErrorInvalidRequest,
			setup: func(c *suCatalog, add func(fleetcatalog.Row), _ func(string, *string)) {
				r := c.row(suVersion, "linux", "386", "deb")
				r.Manifest.Signature = ""
				add(r)
			}},
		{name: "every row signed by a key farmer doesn't trust", version: suVersion, want: controlplane.ErrorInvalidRequest,
			setup: func(*suCatalog, func(fleetcatalog.Row), func(string, *string)) {
				SetFleetKeySource(staticKeys{ks: otherKeys})
			}},
		{name: "no catalog installed", version: suVersion, want: controlplane.ErrorInternal,
			setup: func(*suCatalog, func(fleetcatalog.Row), func(string, *string)) { fleetcatalog.Install(nil) }},
		{name: "no key source configured", version: suVersion, want: controlplane.ErrorInternal,
			setup: func(*suCatalog, func(fleetcatalog.Row), func(string, *string)) { SetFleetKeySource(nil) }},
		{name: "Transit unreachable", version: suVersion, want: controlplane.ErrorInternal,
			setup: func(*suCatalog, func(fleetcatalog.Row), func(string, *string)) {
				SetFleetKeySource(staticKeys{err: errors.New("dial tcp: refused")})
			}},
		{name: "catalog read fails", version: suVersion, want: controlplane.ErrorInternal,
			setup: func(c *suCatalog, _ func(fleetcatalog.Row), _ func(string, *string)) {
				fleetcatalog.Install(failingCatalog{})
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := stubSproutActionDispatch(t, func(string, string) error { return nil })
			c, add, approve := newSUCatalog(t)
			tenant := suTenant
			if tc.tenant != "" {
				tenant = tc.tenant
			}
			if tc.setup != nil {
				tc.setup(c, add, approve)
			}
			reply := handleSproutAction(suRequest(t, tenant, "web-01", controlplane.SelfUpdateParams{Version: tc.version}))
			assertRefused(t, reply, rec, tc.want)
		})
	}
}

// TestSelfUpdate_CrossTenantIsolation: whether a version may be dispatched
// is decided by the sprout's own tenant's approval, never another's. t_a
// approved v2.4.1 and t_b approved v2.3.0: t_b's sprout is refused v2.4.1,
// and a sprout stored under t_b can't be sent anything by a request
// asserting t_a (the point-of-effect check).
func TestSelfUpdate_CrossTenantIsolation(t *testing.T) {
	c, add, approve := newSUCatalog(t)
	add(c.row("v2.3.0", "linux", "amd64", "deb"))
	approve("t_a", ptr(suVersion))
	approve("t_b", ptr("v2.3.0"))
	stored := map[string]string{"web-a": "t_a", "web-b": "t_b"}
	verify := func(tenant, sprout string) error {
		if stored[sprout] != tenant {
			return pki.ErrSproutIDNotFound
		}
		return nil
	}

	rec := stubSproutActionDispatch(t, verify)
	assertRefused(t, handleSproutAction(suRequest(t, "t_b", "web-b", controlplane.SelfUpdateParams{Version: suVersion})),
		rec, controlplane.ErrorInvalidRequest)

	rec = stubSproutActionDispatch(t, verify)
	assertRefused(t, handleSproutAction(suRequest(t, "t_a", "web-b", controlplane.SelfUpdateParams{Version: suVersion})),
		rec, controlplane.ErrorSproutNotFound)

	// Each tenant's own approved version still goes through.
	for sprout, version := range map[string]string{"web-a": suVersion, "web-b": "v2.3.0"} {
		rec = stubSproutActionDispatch(t, verify)
		reply := handleSproutAction(suRequest(t, stored[sprout], sprout, controlplane.SelfUpdateParams{Version: version}))
		if reply.Status != controlplane.StatusDispatched {
			t.Fatalf("%s %s: %+v", sprout, version, reply)
		}
		if calls := rec.all(); len(calls) != 1 || calls[0].tenantID != stored[sprout] {
			t.Fatalf("%s: dispatched %+v", sprout, calls)
		}
	}
}

// The point-of-effect tenant check still runs first: a sprout in another
// tenant is not found, and the catalog isn't consulted for it.
func TestSelfUpdate_TenantCheckStillApplies(t *testing.T) {
	rec := stubSproutActionDispatch(t, func(tenant, _ string) error {
		if tenant != "t_a" {
			return pki.ErrSproutIDNotFound
		}
		return nil
	})
	newSUCatalog(t)
	fleetcatalog.Install(failingCatalog{}) // would turn any catalog read into internal_error
	assertRefused(t, handleSproutAction(suRequest(t, "t_b", "web-01", controlplane.SelfUpdateParams{Version: suVersion})),
		rec, controlplane.ErrorSproutNotFound)
}

// TestSelfUpdate_ThroughRealDispatch: the real catalog check, the real
// sendSelfUpdate and cook.SendStepsEvent. The sprout receives exactly one
// selfupdate step whose properties are exactly {version}, over the
// tenant's own connection.
func TestSelfUpdate_ThroughRealDispatch(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	setupNatsAPIPKI(t)
	legacy := pki.CurrentTenantID()
	writeNKey(t, "", "accepted", "web-01", "UKEY_WEB01")
	cook.RegisterFarmerNatsConn(legacy, nc)
	defer cook.UnregisterFarmerNatsConn(legacy)
	_, _, approve := newSUCatalog(t)
	approve(legacy, ptr(suVersion))
	saas := dialSaaSAPI(t, nc)

	// A sealed stub sprout (sprout_action_fix1_test.go): the dispatch is
	// sealed only, and a sprout with no box key is sent nothing (FIX.1).
	got := make(chan cook.RecipeEnvelope, 1)
	newSealedStubSprout(t, legacy, "web-01").answer(t, nc, "imas.sprouts.web-01.cook",
		payloadbox.PurposeCookRequest, payloadbox.PurposeCookResponse, func(body []byte) any {
			var env cook.RecipeEnvelope
			_ = json.Unmarshal(body, &env)
			got <- env
			return cook.Ack{Acknowledged: true, JobID: env.JobID}
		})
	if err := RegisterSproutAction(nc); err != nil {
		t.Fatal(err)
	}
	// The handler's SUB must reach the server before the SaaS API
	// connection's request does.
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	reply := requestSproutAction(t, saas, controlplane.SproutActionRequest{
		TenantID: legacy, SproutID: "web-01",
		Action: controlplane.SproutAction{Type: controlplane.ActionSelfUpdate, Params: mustJSON(t, controlplane.SelfUpdateParams{Version: suVersion})},
	})
	if reply.Status != controlplane.StatusDispatched || reply.JID == "" {
		t.Fatalf("reply = %+v", reply)
	}
	env := <-got
	if env.JobID != reply.JID || len(env.Steps) != 1 {
		t.Fatalf("envelope = %+v", env)
	}
	step := env.Steps[0]
	if step.Ingredient != fleetsign.SelfUpdateIngredient || step.Method != fleetsign.SelfUpdateMethod ||
		step.ID != cook.StepID(fleetsign.SelfUpdateStepIDPrefix+suVersion) {
		t.Fatalf("step = %+v", step)
	}
	if props := mustJSON(t, step.Properties); string(props) != `{"version":"v2.4.1"}` {
		t.Fatalf("step properties = %s, want exactly the version", props)
	}

	// A version the tenant hasn't approved never reaches the sprout.
	reply = requestSproutAction(t, saas, controlplane.SproutActionRequest{
		TenantID: legacy, SproutID: "web-01",
		Action: controlplane.SproutAction{Type: controlplane.ActionSelfUpdate, Params: mustJSON(t, controlplane.SelfUpdateParams{Version: "v2.5.0"})},
	})
	if reply.Status != controlplane.StatusFailed || reply.ErrorCode != controlplane.ErrorInvalidRequest {
		t.Fatalf("unapproved: reply = %+v", reply)
	}
	select {
	case env := <-got:
		t.Fatalf("an unapproved version reached the sprout: %+v", env)
	default:
	}
}

// enableSelfUpdate turns farmer's self_update switch on for the test, in
// the environment too, so RegisterSproutAction keeps it on.
func enableSelfUpdate(t *testing.T) {
	t.Helper()
	t.Setenv(EnvSelfUpdateEnabled, "true")
	prev := selfUpdateEnabled.Load()
	selfUpdateEnabled.Store(true)
	t.Cleanup(func() { selfUpdateEnabled.Store(prev) })
}

// setWindow sets tenant's rollout window in c's policy table.
func (c *suCatalog) setWindow(tenant string, start, end time.Time) {
	c.t.Helper()
	fleetcatalogtest.SetWindow(c.t, c.db, tenant, &start, &end)
}

// failingCatalog fails every read.
type failingCatalog struct{}

var errCatalogDown = errors.New("pxc: connection refused")

func (failingCatalog) ApprovedManifest(context.Context, string, string, string, string, string) (fleetsign.Manifest, bool, error) {
	return fleetsign.Manifest{}, false, errCatalogDown
}
func (failingCatalog) ApprovedVersion(context.Context, string) (string, bool, error) {
	return "", false, errCatalogDown
}
func (failingCatalog) ReleaseRows(context.Context, string) ([]fleetcatalog.Row, error) {
	return nil, errCatalogDown
}
func (failingCatalog) RolloutWindow(context.Context, string) (*time.Time, *time.Time, bool, error) {
	return nil, nil, false, errCatalogDown
}
