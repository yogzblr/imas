package pki

// Tests for the J.1 control-plane building blocks: CLI box keys (both
// ends), the platform key and SaaS API box key (keygen Job, farmer end,
// SaaS API end) and the sealed refresh proof.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/nats-io/nkeys"
	"github.com/taigrr/jety"

	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
	"github.com/yogzblr/imas/internal/rbac"
)

// ---- CLI box keys ----------------------------------------------------------

// cliUser is one CLI user's local setup: NKey seed and box key file in
// the CLI config, pinned to tenant t_1's current box key.
type cliUser struct {
	id      string
	seed    []byte
	keyFile string
}

// setupCLIStore wires up the farmer side for CLI box keys: the PKI and
// rbac stores, an admin role, the tenant key mock and a Valkey stand-in.
func setupCLIStore(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	gdb := newTestDB(t)
	if err := gdb.AutoMigrate(rbac.Models()...); err != nil {
		t.Fatal(err)
	}
	rbac.SetDB(gdb)
	t.Cleanup(func() { rbac.SetDB(nil) })
	rs := rbac.NewRoleStore()
	if err := rs.Register(&rbac.Role{Name: "admin", Rules: []rbac.Rule{{Action: rbac.ActionAdmin, Scope: "*"}}}); err != nil {
		t.Fatal(err)
	}
	auth.SetPolicy(rs, rbac.NewUserRoleMap(), nil)
	t.Cleanup(func() { auth.SetPolicy(nil, nil, nil) })
	setupTenantBoxOpenBao(t)
	return withTestReplayCache(t)
}

// newCLIUser makes a user known to the policy, gives them a CLI box key,
// and points the CLI config at them (the "current" CLI is the last one
// made or selected with use).
func newCLIUser(t *testing.T, register bool) *cliUser {
	t.Helper()
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := kp.Seed()
	id, _ := kp.PublicKey()
	auth.CurrentPolicy().Users.Set(id, "admin")
	u := &cliUser{id: id, seed: seed, keyFile: filepath.Join(t.TempDir(), "cli-box.key")}
	u.use(t)
	pub, err := GenerateCLIBoxKey(u.keyFile, false)
	if err != nil {
		t.Fatal(err)
	}
	if register {
		if err := RegisterCLIBoxKey("t_1", id, pub); err != nil {
			t.Fatalf("RegisterCLIBoxKey: %v", err)
		}
	}
	return u
}

// use makes u the CLI whose config is loaded, pinned to t_1's key.
func (u *cliUser) use(t *testing.T) {
	t.Helper()
	tk, err := GetTenantX25519PublicKey("t_1")
	if err != nil {
		t.Fatal(err)
	}
	jety.Set("privkey", string(u.seed))
	jety.Set(CLIBoxPrivFileKey, u.keyFile)
	jety.Set(CLITenantBoxPubKey, tk)
	jety.Set(CLITenantIDKey, "t_1")
	t.Cleanup(func() {
		for _, k := range []string{"privkey", CLIBoxPrivFileKey, CLITenantBoxPubKey, CLITenantIDKey} {
			jety.Set(k, "")
		}
	})
}

func TestCLISealedRequestRoundTrip(t *testing.T) {
	setupCLIStore(t)
	alice := newCLIUser(t, true)
	data, id, principal, err := CLISealRequest(payloadbox.PurposeCLIRequest, "jobs.list", map[string]int{"limit": 5})
	if err != nil {
		t.Fatal(err)
	}
	if principal != alice.id {
		t.Fatalf("principal %s, want %s", principal, alice.id)
	}
	if bytes.Contains(data, []byte("limit")) {
		t.Fatal("the request's params are readable on the wire")
	}
	msg, body, sealedUnder, err := OpenFromCLI("t_1", alice.id, payloadbox.PurposeCLIRequest, "jobs.list", "imas.api.jobs.list", data)
	if err != nil {
		t.Fatalf("OpenFromCLI: %v", err)
	}
	pub, _ := CLIBoxPub()
	if msg.ID != id || sealedUnder != pub || string(body.Params) != `{"limit":5}` {
		t.Fatalf("opened %+v %+v under %s", msg, body, sealedUnder)
	}
	reply, err := SealToCLI("t_1", alice.id, payloadbox.Reply{
		Purpose: payloadbox.PurposeCLIReply, ReplyTo: id, Method: "jobs.list", Subject: "imas.api.jobs.list", Result: []string{"j1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rb, err := CLIOpenReply("jobs.list", id, reply)
	if err != nil {
		t.Fatalf("CLIOpenReply: %v", err)
	}
	if string(rb.Result) != `["j1"]` {
		t.Fatalf("result %s", rb.Result)
	}
	// A reply to another request is refused.
	other, _ := payloadbox.NewID()
	if _, err := CLIOpenReply("jobs.list", other, reply); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("a reply to another request: %v", err)
	}
}

func TestOpenFromCLIRefusals(t *testing.T) {
	setupCLIStore(t)
	bob := newCLIUser(t, true)
	unregistered := newCLIUser(t, false)
	alice := newCLIUser(t, true)
	data, _, _, err := CLISealRequest(payloadbox.PurposeCLIRequest, "jobs.list", nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, open := range map[string]func() error{
		// The header claims bob: alice's request doesn't open under
		// bob's key, and wouldn't name him if it did.
		"wrong principal": func() error {
			_, _, _, err := OpenFromCLI("t_1", bob.id, payloadbox.PurposeCLIRequest, "jobs.list", "imas.api.jobs.list", data)
			return err
		},
		"wrong method": func() error {
			_, _, _, err := OpenFromCLI("t_1", alice.id, payloadbox.PurposeCLIRequest, "jobs.delete", "imas.api.jobs.list", data)
			return err
		},
		"wrong subject": func() error {
			_, _, _, err := OpenFromCLI("t_1", alice.id, payloadbox.PurposeCLIRequest, "jobs.list", "imas.api.jobs.delete", data)
			return err
		},
		"wrong purpose": func() error {
			_, _, _, err := OpenFromCLI("t_1", alice.id, payloadbox.PurposeCLIUserKeySubmit, "jobs.list", "imas.api.jobs.list", data)
			return err
		},
		"wrong tenant": func() error {
			_, _, _, err := OpenFromCLI("t_2", alice.id, payloadbox.PurposeCLIRequest, "jobs.list", "imas.api.jobs.list", data)
			return err
		},
	} {
		if err := open(); !errors.Is(err, payloadbox.ErrOpen) {
			t.Errorf("%s: %v, want ErrOpen", name, err)
		}
	}
	// A user with no registered key can't make a sealed request at all,
	// and nothing falls back to anything weaker.
	unregistered.use(t)
	data, _, _, err = CLISealRequest(payloadbox.PurposeCLIRequest, "jobs.list", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := OpenFromCLI("t_1", unregistered.id, payloadbox.PurposeCLIRequest, "jobs.list", "imas.api.jobs.list", data); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("unregistered user: %v, want ErrOpen", err)
	}
}

// imas auth rotate-key, both ends: the submission is sealed under the
// current key, farmer records the new key and replies to it, and the
// reply opening under the pending key is what promotes it.
func TestCLIBoxKeyRotationRoundTrip(t *testing.T) {
	setupCLIStore(t)
	alice := newCLIUser(t, true)
	oldPub, _ := CLIBoxPub()
	data, id, _, newPub, err := BeginCLIBoxKeyRotation()
	if err != nil {
		t.Fatal(err)
	}
	// A retry reuses the same pending key.
	if _, _, _, again, err := BeginCLIBoxKeyRotation(); err != nil || again != newPub {
		t.Fatalf("second BeginCLIBoxKeyRotation = %s, %v", again, err)
	}
	_, body, sealedUnder, err := OpenFromCLI("t_1", alice.id, payloadbox.PurposeCLIUserKeySubmit, MethodAuthRotateKey,
		CLIAPISubjectPrefix+MethodAuthRotateKey, data)
	if err != nil || sealedUnder != oldPub {
		t.Fatalf("OpenFromCLI: under %s, %v", sealedUnder, err)
	}
	recorded, err := RecordCLIBoxKeySubmission("t_1", alice.id, sealedUnder, body)
	if err != nil || recorded != newPub {
		t.Fatalf("RecordCLIBoxKeySubmission = %s, %v", recorded, err)
	}
	reply, err := SealToCLI("t_1", alice.id, payloadbox.Reply{Purpose: payloadbox.PurposeCLIReply, ReplyTo: id,
		Method: MethodAuthRotateKey, Subject: CLIAPISubjectPrefix + MethodAuthRotateKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CLIOpenReply(MethodAuthRotateKey, id, reply); err != nil {
		t.Fatalf("CLIOpenReply: %v", err)
	}
	if cur, _ := CLIBoxPub(); cur != newPub {
		t.Fatalf("current key %s after the reply, want %s", cur, newPub)
	}
	if fileExists(cliPendingBoxPrivFile()) {
		t.Error("the pending key file is still there")
	}
	// The next request goes under the new key, and the old one is in its
	// grace window on farmer.
	data, _, _, err = CLISealRequest(payloadbox.PurposeCLIRequest, "jobs.list", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, under, err := OpenFromCLI("t_1", alice.id, payloadbox.PurposeCLIRequest, "jobs.list", "imas.api.jobs.list", data); err != nil || under != newPub {
		t.Fatalf("request after rotation: under %s, %v", under, err)
	}
	if _, grace, _ := auth.ValidCLIBoxKeys("t_1", alice.id); len(grace) != 1 || grace[0] != oldPub {
		t.Errorf("grace keys %v, want [%s]", grace, oldPub)
	}
}

func TestRegisterCLIBoxKeyRefusesClaimedKeys(t *testing.T) {
	setupCLIStore(t)
	u := newCLIUser(t, false)
	tk, _ := GetTenantX25519PublicKey("t_1")
	if err := RegisterCLIBoxKey("t_1", u.id, tk); !errors.Is(err, ErrBoxKeyClaimed) {
		t.Errorf("the tenant's own key: %v, want ErrBoxKeyClaimed", err)
	}
	sproutPub := otherBoxPub(t)
	if err := upsertSproutBoxKeyActive("t_9", "web-01", sproutPub); err != nil {
		t.Fatal(err)
	}
	if err := RegisterCLIBoxKey("t_1", u.id, sproutPub); !errors.Is(err, ErrBoxKeyClaimed) {
		t.Errorf("a sprout's key in another tenant: %v, want ErrBoxKeyClaimed", err)
	}
	if err := RegisterCLIBoxKey("not a tenant!", u.id, otherBoxPub(t)); err == nil {
		t.Error("an invalid tenant ID was accepted")
	}
}

func TestGenerateCLIBoxKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "imas", "cli-box.key")
	pub, err := GenerateCLIBoxKey(path, false)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, %v", st.Mode().Perm(), err)
	}
	if _, err := GenerateCLIBoxKey(path, false); !errors.Is(err, ErrCLIBoxKeyExists) {
		t.Errorf("overwrite without force: %v", err)
	}
	again, err := GenerateCLIBoxKey(path, true)
	if err != nil || again == pub {
		t.Errorf("force: %s, %v", again, err)
	}
}

// ---- platform key and SaaS API box key -------------------------------------

// setupControlPlaneKeys runs the keygen Job against the mock OpenBao and
// returns the SaaS API's end, built from what the Job wrote, as the SaaS
// API's External Secret would deliver it.
func setupControlPlaneKeys(t *testing.T) (*tenantboxtest.Server, *SaaSAPIBox) {
	t.Helper()
	srv := setupTenantBoxOpenBao(t)
	InvalidatePlatformBoxKeys()
	t.Cleanup(InvalidatePlatformBoxKeys)
	t.Setenv(EnvCPBoxOpenBaoAddr, srv.URL)
	t.Setenv(EnvCPBoxOpenBaoAuthMethod, "token")
	t.Setenv(EnvCPBoxOpenBaoToken, tenantboxtest.Token)
	t.Setenv(EnvCPBoxOpenBaoKVPath, tenantboxtest.BasePath)
	var stderr bytes.Buffer
	if code := RunControlPlaneBoxKeys(nil, &stderr); code != 0 {
		t.Fatalf("keygen job exit %d: %s", code, stderr.String())
	}
	if bytes.Contains(stderr.Bytes(), []byte(srv.Versions(tenantboxtest.BasePath + "/platform")[0].Data["priv"])) {
		t.Fatal("the job printed a private key")
	}
	saas := srv.Versions(tenantboxtest.BasePath + "/saasapi-box")[0].Data
	pubs := srv.Versions(tenantboxtest.BasePath + "/controlplane-pub")[0].Data
	privFile := filepath.Join(t.TempDir(), "saasapi-box.key")
	if err := os.WriteFile(privFile, []byte(saas["priv"]), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := LoadSaaSAPIBox(privFile, pubs["platform_pub"])
	if err != nil {
		t.Fatal(err)
	}
	return srv, b
}

func TestControlPlaneKeygenJob(t *testing.T) {
	srv, _ := setupControlPlaneKeys(t)
	platform := srv.Versions(tenantboxtest.BasePath + "/platform")
	saas := srv.Versions(tenantboxtest.BasePath + "/saasapi-box")
	pubs := srv.Versions(tenantboxtest.BasePath + "/controlplane-pub")
	if len(platform) != 1 || len(saas) != 1 || len(pubs) != 1 {
		t.Fatalf("versions: %d %d %d", len(platform), len(saas), len(pubs))
	}
	if pubs[0].Data["platform_pub"] != platform[0].Data["pub"] || pubs[0].Data["saasapi_box_pub"] != saas[0].Data["pub"] {
		t.Fatalf("published %v", pubs[0].Data)
	}
	if _, ok := pubs[0].Data["priv"]; ok {
		t.Fatal("a private key in the public secret")
	}
	// A re-run (every helm upgrade) changes nothing.
	res, err := EnsureControlPlaneBoxKeys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if res.PlatformCreated || res.SaaSCreated || res.PublicWritten {
		t.Fatalf("re-run changed something: %+v", res)
	}
	if len(srv.Versions(tenantboxtest.BasePath+"/platform")) != 1 || len(srv.Versions(tenantboxtest.BasePath+"/controlplane-pub")) != 1 {
		t.Fatal("re-run wrote a new version")
	}
	// Without its OpenBao identity the job is a usage error.
	t.Setenv(EnvCPBoxOpenBaoAddr, "")
	if code := RunControlPlaneBoxKeys(nil, &bytes.Buffer{}); code != 2 {
		t.Errorf("unconfigured exit %d, want 2", code)
	}
}

func TestPlatformBoxNotProvisioned(t *testing.T) {
	setupTenantBoxOpenBao(t)
	InvalidatePlatformBoxKeys()
	t.Cleanup(InvalidatePlatformBoxKeys)
	if _, err := PlatformBoxKeys(); !errors.Is(err, ErrPlatformBoxNotProvisioned) {
		t.Fatalf("PlatformBoxKeys = %v, want ErrPlatformBoxNotProvisioned", err)
	}
	if _, _, err := OpenFromSaaSAPI(payloadbox.PurposeSaaSSproutAction, "sprout.action", "internal.sprout.action", []byte("{}")); err == nil {
		t.Fatal("opened with no platform key")
	}
}

// Every SaaS API purpose round-trips: requests the SaaS API seals open on
// farmer, farmer's reply and results open on the SaaS API.
func TestSaaSAPISealedRoundTrips(t *testing.T) {
	_, saas := setupControlPlaneKeys(t)
	for _, c := range []struct{ purpose, method, subject, reply string }{
		{payloadbox.PurposeSaaSTenantProvision, "tenant.provision", "internal.tenant.provision", ""},
		{payloadbox.PurposeSaaSTenantDeprovision, "tenant.deprovision", "internal.tenant.deprovision", ""},
		{payloadbox.PurposeSaaSSproutAction, "sprout.action", "internal.sprout.action", payloadbox.PurposeSaaSSproutActionReply},
	} {
		data, id, err := saas.SealRequest(c.purpose, c.method, c.subject, map[string]string{"tenant_id": "t_1"})
		if err != nil {
			t.Fatal(err)
		}
		msg, body, err := OpenFromSaaSAPI(c.purpose, c.method, c.subject, data)
		if err != nil {
			t.Fatalf("%s: OpenFromSaaSAPI: %v", c.purpose, err)
		}
		if msg.ID != id || string(body.Params) != `{"tenant_id":"t_1"}` {
			t.Fatalf("%s: opened %+v %+v", c.purpose, msg, body)
		}
		// Moved to another method's subject, it doesn't open.
		if _, _, err := OpenFromSaaSAPI(c.purpose, "tenant.deprovision", "internal.tenant.deprovision", data); err == nil && c.method != "tenant.deprovision" {
			t.Errorf("%s: opened on another subject", c.purpose)
		}
		if c.reply == "" {
			continue
		}
		reply, err := SealReplyToSaaSAPI(payloadbox.Reply{Purpose: c.reply, ReplyTo: id, Method: c.method, Subject: c.subject, Result: "ok"})
		if err != nil {
			t.Fatal(err)
		}
		rb, err := saas.OpenReply(c.reply, c.method, c.subject, id, reply)
		if err != nil || string(rb.Result) != `"ok"` {
			t.Fatalf("%s: OpenReply %+v, %v", c.reply, rb, err)
		}
	}
	for _, c := range []struct{ purpose, method string }{
		{payloadbox.PurposeSaaSTenantProvisioned, "tenant.provisioned"},
		{payloadbox.PurposeSaaSTenantDeprovisioned, "tenant.deprovisioned"},
	} {
		subject := "internal." + c.method + ".job-7"
		data, _, err := SealResultToSaaSAPI(payloadbox.Call{Purpose: c.purpose, Method: c.method, Subject: subject, Params: map[string]string{"job_id": "job-7"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := saas.OpenResult(c.purpose, c.method, "internal."+c.method+".job-8", data); !errors.Is(err, payloadbox.ErrOpen) {
			t.Errorf("%s: a result moved to another job's subject: %v", c.purpose, err)
		}
		if _, err := saas.OpenResult(c.purpose, c.method, subject, data); err != nil {
			t.Fatalf("%s: OpenResult: %v", c.purpose, err)
		}
		if _, err := saas.OpenResult(c.purpose, c.method, subject, data); !errors.Is(err, payloadbox.ErrReplayed) {
			t.Errorf("%s: a replayed result: %v, want ErrReplayed", c.purpose, err)
		}
	}
}

// A request sealed with a key that isn't the registered SaaS API box key
// (a bus that made its own) doesn't open, and a farmer reply doesn't open
// as a SaaS API request (reflection).
func TestOpenFromSaaSAPIRefusesOtherKeys(t *testing.T) {
	_, saas := setupControlPlaneKeys(t)
	impostor := newTestBoxKeyPair(t)
	fake, err := NewSaaSAPIBox(impostor.priv, encodeBoxPub(saas.platformPubs[0]))
	if err != nil {
		t.Fatal(err)
	}
	data, _, err := fake.SealRequest(payloadbox.PurposeSaaSSproutAction, "sprout.action", "internal.sprout.action", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenFromSaaSAPI(payloadbox.PurposeSaaSSproutAction, "sprout.action", "internal.sprout.action", data); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("impostor: %v, want ErrOpen", err)
	}
	id, _ := payloadbox.NewID()
	reply, err := SealReplyToSaaSAPI(payloadbox.Reply{Purpose: payloadbox.PurposeSaaSSproutActionReply, ReplyTo: id, Method: "sprout.action", Subject: "internal.sprout.action"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenFromSaaSAPI(payloadbox.PurposeSaaSSproutAction, "sprout.action", "internal.sprout.action", reply); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("reflected reply: %v, want ErrOpen", err)
	}
	if _, err := NewSaaSAPIBox(impostor.priv, encodeBoxPub(impostor.pub)); err == nil {
		t.Error("a SaaS API box pinned to its own key")
	}
}

// ---- sealed refresh (Decision C) ------------------------------------------

func sproutNKeyPub(t *testing.T) string {
	t.Helper()
	seed, err := os.ReadFile(config.NKeySproutPrivFile)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := nkeys.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	return pub
}

func TestSealedRefreshRoundTripAndRefusals(t *testing.T) {
	enrollForTest(t)
	nkeyPub := sproutNKeyPub(t)
	sealed, _, err := SproutSealedRefresh("web-01", nkeyPub)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(nkeyPub)) {
		t.Fatal("the proof's body is readable")
	}
	tid, sid, err := OpenSealedRefresh(t.Context(), nkeyPub, sealed)
	if err != nil || tid != "t_1" || sid != "web-01" {
		t.Fatalf("OpenSealedRefresh = %s %s %v", tid, sid, err)
	}
	// Replayed, on this replica or another (one Valkey): refused.
	if _, _, err := OpenSealedRefresh(t.Context(), nkeyPub, sealed); !errors.Is(err, ErrEnrollmentFailed) {
		t.Errorf("replayed: %v", err)
	}
	// Presented with another sprout's NKey: refused.
	other, _ := nkeys.CreateUser()
	otherPub, _ := other.PublicKey()
	fresh, _, _ := SproutSealedRefresh("web-01", nkeyPub)
	if _, _, err := OpenSealedRefresh(t.Context(), otherPub, fresh); !errors.Is(err, ErrEnrollmentFailed) {
		t.Errorf("another NKey: %v", err)
	}
	// Stale: issued more than five minutes ago.
	orig := enrollNow
	enrollNow = func() time.Time { return orig().Add(10 * time.Minute) }
	t.Cleanup(func() { enrollNow = orig })
	if _, _, err := OpenSealedRefresh(t.Context(), nkeyPub, fresh); !errors.Is(err, ErrEnrollmentFailed) {
		t.Errorf("stale: %v", err)
	}
	enrollNow = orig
	// Sealed for something else (a cmd.run reply): refused.
	wrong, _ := SproutSealForFarmer("web-01", payloadbox.PurposeCmdRunResponse, "", sealedRefreshBody{NKeyPub: nkeyPub, Timestamp: time.Now().Unix()})
	if _, _, err := OpenSealedRefresh(t.Context(), nkeyPub, wrong); !errors.Is(err, ErrEnrollmentFailed) {
		t.Errorf("wrong purpose: %v", err)
	}
	if _, _, err := OpenSealedRefresh(t.Context(), nkeyPub, fresh); err != nil {
		t.Errorf("the fresh proof after all that: %v", err)
	}
}

func TestSealedRefreshFailsClosedWithoutValkey(t *testing.T) {
	enrollForTest(t)
	nkeyPub := sproutNKeyPub(t)
	sealed, _, err := SproutSealedRefresh("web-01", nkeyPub)
	if err != nil {
		t.Fatal(err)
	}
	SetReplayCacheClient(nil)
	if _, _, err := OpenSealedRefresh(t.Context(), nkeyPub, sealed); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("no Valkey: %v", err)
	}
}

// A sprout whose tenant pin predates a rotation (outside the grace
// window) still refreshes: farmer tries every retained key, as
// continuity does.
func TestSealedRefreshOpensUnderARetainedTenantKey(t *testing.T) {
	enrollForTest(t)
	withTenantBoxGrace(t, 0)
	nkeyPub := sproutNKeyPub(t)
	if _, err := RotateTenantX25519Keypair("t_1", false); err != nil {
		t.Fatal(err)
	}
	sealed, _, err := SproutSealedRefresh("web-01", nkeyPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenSealedRefresh(t.Context(), nkeyPub, sealed); err != nil {
		t.Fatalf("pinned to the previous key: %v", err)
	}
}

func TestClaimSealedMessage(t *testing.T) {
	mr := withTestReplayCache(t)
	id, _ := payloadbox.NewID()
	if err := ClaimSealedMessage(t.Context(), "t_1", "UALICE", id); err != nil {
		t.Fatal(err)
	}
	if err := ClaimSealedMessage(t.Context(), "t_1", "UALICE", id); !errors.Is(err, ErrSealedReplayed) {
		t.Errorf("second claim: %v", err)
	}
	// Keyed on the tenant and principal as well as the ID.
	if err := ClaimSealedMessage(t.Context(), "t_2", "UALICE", id); err != nil {
		t.Errorf("another tenant: %v", err)
	}
	if ttl := mr.TTL(SealedClaimKey("t_1", "UALICE", id)); ttl != SealedClaimTTL {
		t.Errorf("TTL %v, want %v", ttl, SealedClaimTTL)
	}
	for _, bad := range [][3]string{{"t:1", "U", id}, {"t_1", "", id}, {"t_1", "U", "a b"}} {
		if err := ClaimSealedMessage(t.Context(), bad[0], bad[1], bad[2]); !errors.Is(err, ErrSealedClaimUnavailable) {
			t.Errorf("%v: %v", bad, err)
		}
	}
	mr.SetError("down")
	if err := ClaimSealedMessage(t.Context(), "t_1", "UALICE", "ab12"); !errors.Is(err, ErrSealedClaimUnavailable) {
		t.Errorf("Valkey down: %v", err)
	}
}

// The first admin's boxpub, imported from farmer's config at start, gets
// the same cross-principal check as an API registration (pki.SetDB
// installs it): a sprout's box key is refused, a fresh key is imported.
func TestConfigBoxPubImportChecksOtherPrincipals(t *testing.T) {
	setupCLIStore(t)
	kp, _ := nkeys.CreateAccount()
	admin, _ := kp.PublicKey()
	sproutPub := otherBoxPub(t)
	if err := upsertSproutBoxKeyActive("t_9", "web-01", sproutPub); err != nil {
		t.Fatal(err)
	}
	load := func(boxpub string) {
		t.Helper()
		jety.Set("roles", map[string]interface{}{"admin": []interface{}{map[string]interface{}{"action": "admin"}}})
		jety.Set("users", map[string]interface{}{"admin": []interface{}{map[string]interface{}{"pubkey": admin, "boxpub": boxpub}}})
		if err := auth.LoadPolicy(); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { jety.Set("roles", nil); jety.Set("users", nil) })
	load(sproutPub)
	if _, _, err := auth.ValidCLIBoxKeys(CurrentTenantID(), admin); !errors.Is(err, auth.ErrNoActiveCLIBoxKey) {
		t.Fatalf("a sprout's box key was imported as a CLI key: %v", err)
	}
	fresh := otherBoxPub(t)
	load(fresh)
	if active, _, err := auth.ValidCLIBoxKeys(CurrentTenantID(), admin); err != nil || active != fresh {
		t.Fatalf("fresh key: %q, %v", active, err)
	}
}
