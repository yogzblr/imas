package natsapi

// J.3: the sealed router (sealedrouter.go) end to end on an embedded bus.
// FLAG FOR SECURITY REVIEW. The CLI side here is the real client package
// (client.SealedRequest, the path every CLI command takes), the farmer
// side the real Subscribe; tenant keys come from a mock OpenBao and the
// cluster-wide claim from miniredis (setupSealedEnv).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/taigrr/jety"

	"github.com/yogzblr/imas/internal/api/client"
	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/audit"
	intauth "github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/rbac"
)

// adminCaller makes UTESTADMIN an admin in a fresh policy and returns it
// as a caller in tenantID, for handler unit tests that need a user whose
// role allows everything.
func adminCaller(t *testing.T, tenantID string) apiCaller {
	t.Helper()
	rs := rbac.NewRoleStore()
	if err := rs.Register(&rbac.Role{Name: "admin", Rules: []rbac.Rule{{Action: rbac.ActionAdmin, Scope: "*"}}}); err != nil {
		t.Fatal(err)
	}
	urm := rbac.NewUserRoleMap()
	urm.Set("UTESTADMIN", "admin")
	intauth.SetPolicy(rs, urm, nil)
	t.Cleanup(func() { intauth.SetPolicy(nil, nil, nil) })
	return apiCaller{TenantID: tenantID, UserID: "UTESTADMIN"}
}

// sealedFarmer is one farmer replica subscribed on its own connection to
// an embedded bus, in tenant t_1, with the sealed environment set up.
type sealedFarmer struct {
	env *sealedEnv
	nc  *nats.Conn // the CLI's connection
}

func startSealedFarmer(t *testing.T) *sealedFarmer {
	t.Helper()
	env := setupSealedEnv(t)
	nc, cleanup := startEmbeddedNATS(t)
	t.Cleanup(cleanup)
	if err := Subscribe(nc, "t_1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ClearNatsConn("t_1") })
	return &sealedFarmer{env: env, nc: nc}
}

// call is the CLI's sealed request for method, as the current jety user.
func (f *sealedFarmer) call(method string, params any) (json.RawMessage, error) {
	return client.SealedRequest(f.nc, payloadbox.PurposeCLIRequest, method, params, 5*time.Second)
}

// raw sends m and returns the answer as it came off the bus.
func (f *sealedFarmer) raw(t *testing.T, m *nats.Msg) *nats.Msg {
	t.Helper()
	m.Reply = ""
	resp, err := f.nc.RequestMsg(m, 5*time.Second)
	if err != nil {
		t.Fatalf("request %s: %v", m.Subject, err)
	}
	return resp
}

func wantRefusal(t *testing.T, name string, resp *nats.Msg, code string) {
	t.Helper()
	if got := resp.Header.Get(payloadbox.ErrorHeader); got != code || len(resp.Data) != 0 {
		t.Fatalf("%s: answered %v %q, want refusal %s with no body", name, resp.Header, resp.Data, code)
	}
}

// The whole path: a CLI user's sealed request runs as that user and the
// sealed reply opens on the CLI; who the caller is comes from the key the
// request opened under.
func TestSealedRouterRunsAsTheVerifiedUser(t *testing.T) {
	f := startSealedFarmer(t)
	u := newSealedCLIUser(t)
	intauth.CurrentPolicy().Users.SetUsername(u.id, "alice")

	res, err := f.call(MethodAuthWhoAmI, map[string]string{"token": "x", "pubkey": "USOMEONEELSE"})
	if err != nil {
		t.Fatal(err)
	}
	var who apitypes.UserInfo
	if err := json.Unmarshal(res, &who); err != nil || who.Pubkey != u.id || who.RoleName != "admin" || who.Username != "alice" {
		t.Fatalf("whoami %+v, %v", who, err)
	}

	res, err = f.call(MethodAuthLogin, nil)
	if err != nil {
		t.Fatal(err)
	}
	var login apitypes.LoginResponse
	if err := json.Unmarshal(res, &login); err != nil || !login.Authenticated || login.Pubkey != u.id || !login.IsAdmin {
		t.Fatalf("login %+v, %v", login, err)
	}

	// A handler's error travels inside the sealed reply.
	if _, err := f.call(MethodJobsGet, map[string]string{}); err == nil || !strings.Contains(err.Error(), "jid is required") {
		t.Fatalf("handler error: %v", err)
	}
}

// Health and version still answer an unsealed request in plaintext, for
// monitoring; nothing else does, and a sealed health gets a sealed reply.
func TestSealedRouterPlaintext(t *testing.T) {
	f := startSealedFarmer(t)
	newSealedCLIUser(t)
	for _, m := range []string{MethodVersion, MethodHealth} {
		resp := f.raw(t, nats.NewMsg(Subject(m)))
		var r response
		if resp.Header.Get(payloadbox.Header) != "" || json.Unmarshal(resp.Data, &r) != nil {
			t.Fatalf("%s plaintext: %v %q", m, resp.Header, resp.Data)
		}
		if _, err := f.call(m, nil); err != nil {
			t.Fatalf("%s sealed: %v", m, err)
		}
	}
	for _, m := range []string{MethodJobsList, MethodAuthWhoAmI, MethodAuthAddUser, MethodRecipesList} {
		plain := nats.NewMsg(Subject(m))
		plain.Data = []byte(`{}`)
		wantRefusal(t, m+" in plaintext", f.raw(t, plain), payloadbox.ErrorCodeEncryptionRequired)
	}
}

// The forged-token regression (SEC.0, closed by J.3). A compromised bus
// gets the CLI's NKey to sign any nonce at CONNECT (internal/api/client's
// TestConnectNonceSignatureIsAllTheBusGets), so it can build exactly what
// a bearer token used to be: a signature over an expiry, here 2099. None
// of it is accepted any more, in any form:
//
//   - as the old plaintext request with a token field: refused,
//     encryption-required, for every method, admin ones included;
//   - inside a sealed request the bus seals with a key of its own and
//     labels as the victim (Imas-Principal): refused, open-failed;
//   - with the captured signature bytes standing in as the sealed body:
//     refused, open-failed.
//
// And a genuine sealed admin request the bus captured can't be replayed:
// not to the same replica (replay guard), not to another (Valkey claim).
func TestForgedTokenRegression(t *testing.T) {
	f := startSealedFarmer(t)
	admin := newSealedCLIUser(t)

	// What the bus gets from one CONNECT.
	kp, err := nkeys.FromSeed(admin.seed)
	if err != nil {
		t.Fatal(err)
	}
	const nonce = "2099-01-01T00:00:00Z"
	sig, err := kp.Sign([]byte(nonce))
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := json.Marshal(map[string]string{"expires": nonce, "pubkey": admin.id, "sig": base64.StdEncoding.EncodeToString(sig)})
	token := base64.StdEncoding.EncodeToString(forged)

	newUser, _ := nkeys.CreateAccount()
	newID, _ := newUser.PublicKey()
	addParams := map[string]string{"token": token, "pubkey": newID, "role": "admin", "boxpub": newBoxPubForTest(t)}

	// 1. The old wire format.
	for _, m := range []string{MethodAuthAddUser, MethodAuthWhoAmI, MethodPKIAccept, MethodCmdRun} {
		plain := nats.NewMsg(Subject(m))
		plain.Data, _ = json.Marshal(addParams)
		wantRefusal(t, "plaintext "+m+" with a forged token", f.raw(t, plain), payloadbox.ErrorCodeEncryptionRequired)
	}

	// 2. Sealed by the bus under its own key, labelled as the admin.
	busUser := &cliUser{id: admin.id, seed: admin.seed, tenant: "t_1", keyFile: t.TempDir() + "/bus.key"}
	if _, err := pki.GenerateCLIBoxKey(busUser.keyFile, false); err != nil {
		t.Fatal(err)
	}
	busUser.use(t)
	m, _ := cliRequest(t, MethodAuthAddUser, addParams)
	wantRefusal(t, "sealed under the bus's key as the admin", f.raw(t, m), payloadbox.ErrorCodeOpenFailed)

	// 3. The captured signature as the body.
	asBody := nats.NewMsg(Subject(MethodAuthAddUser))
	asBody.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	asBody.Header.Set(payloadbox.PrincipalHeader, admin.id)
	asBody.Data = sig
	wantRefusal(t, "the CONNECT signature as a sealed body", f.raw(t, asBody), payloadbox.ErrorCodeOpenFailed)

	if role, _ := intauth.UserIdentity(newID); role != "" {
		t.Fatalf("the bus registered %s as %q", newID, role)
	}

	// 4. A genuine sealed admin request, captured and replayed.
	admin.use(t)
	genuine, _ := cliRequest(t, MethodAuthAddUser, map[string]string{"pubkey": newID, "role": "admin", "boxpub": newBoxPubForTest(t)})
	first := f.raw(t, genuine)
	if first.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		t.Fatalf("genuine add: %v", first.Header)
	}
	if err := intauth.RemoveUser(newID); err != nil {
		t.Fatal(err)
	}
	wantRefusal(t, "replay to the same replica", f.raw(t, genuine), payloadbox.ErrorCodeOpenFailed)
	// Another replica: its own replay guard, the shared Valkey.
	replicaB := newSealedAPI()
	_, err = replicaB.openCLIRequest(context.Background(), "t_1", genuine)
	if !errors.Is(err, pki.ErrSealedReplayed) {
		t.Fatalf("replay to another replica: %v, want ErrSealedReplayed", err)
	}
	if role, _ := intauth.UserIdentity(newID); role != "" {
		t.Fatal("a replay re-added the removed user")
	}
}

func newBoxPubForTest(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/k"
	pub, err := pki.GenerateCLIBoxKey(path, false)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// Wrong key, wrong user, a revoked key, a removed user, a method not
// granted.
func TestSealedRouterRefusals(t *testing.T) {
	f := startSealedFarmer(t)
	bob := newSealedCLIUser(t)
	alice := newSealedCLIUser(t) // the current CLI

	// Wrong user: alice's request labelled as bob.
	m, _ := cliRequest(t, MethodJobsList, nil)
	m.Header.Set(payloadbox.PrincipalHeader, bob.id)
	wantRefusal(t, "wrong user", f.raw(t, m), payloadbox.ErrorCodeOpenFailed)

	// Wrong key: alice's CLI with a key farmer never registered.
	path := t.TempDir() + "/other.key"
	if _, err := pki.GenerateCLIBoxKey(path, false); err != nil {
		t.Fatal(err)
	}
	jety.Set(pki.CLIBoxPrivFileKey, path)
	_, err := f.call(MethodPKIList, nil)
	var refused *client.RefusedError
	if !errors.As(err, &refused) || refused.Code != payloadbox.ErrorCodeOpenFailed {
		t.Fatalf("wrong key: %v", err)
	}
	alice.use(t)
	if _, err := f.call(MethodPKIList, nil); err != nil {
		t.Fatalf("alice's own key: %v", err)
	}

	// A method not granted: a viewer asking for an admin method gets a
	// sealed access-denied, and nothing runs.
	intauth.CurrentPolicy().Users.Set(alice.id, "viewer")
	if err := intauth.CurrentPolicy().Roles.Register(&rbac.Role{Name: "viewer", Rules: []rbac.Rule{{Action: rbac.ActionView, Scope: "*"}}}); err != nil {
		t.Fatal(err)
	}
	carol, _ := nkeys.CreateAccount()
	carolID, _ := carol.PublicKey()
	_, err = f.call(MethodAuthAddUser, map[string]string{"pubkey": carolID, "role": "admin", "boxpub": newBoxPubForTest(t)})
	if err == nil || err.Error() != rbac.ErrAccessDenied.Error() {
		t.Fatalf("viewer adding a user: %v, want access denied", err)
	}
	if role, _ := intauth.UserIdentity(carolID); role != "" {
		t.Fatal("a viewer added a user")
	}
	intauth.CurrentPolicy().Users.Set(alice.id, "admin")

	// A revoked key: nothing opens under it from the next request on.
	if err := intauth.RevokeCLIBoxKeys("t_1", alice.id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.call(MethodPKIList, nil); !errors.As(err, &refused) || refused.Code != payloadbox.ErrorCodeOpenFailed {
		t.Fatalf("revoked key: %v", err)
	}
}

// Replayed to two replicas sharing Valkey: a mutating request runs once,
// whichever replica sees the replay.
func TestSealedRouterReplayAcrossReplicas(t *testing.T) {
	env := setupSealedEnv(t)
	newSealedCLIUser(t)
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	var runs atomic.Int32
	run := func(apiCaller, json.RawMessage) (any, error) { runs.Add(1); return "ok", nil }
	replicas := []*sealedAPI{newSealedAPI(), newSealedAPI()}
	var answers []*nats.Msg
	for _, r := range replicas {
		r := r
		sub, err := nc.Subscribe(Subject(MethodPropsSet), func(m *nats.Msg) { r.serve("t_1", MethodPropsSet, run, m) })
		if err != nil {
			t.Fatal(err)
		}
		defer sub.Unsubscribe()
	}
	m, _ := cliRequest(t, MethodPropsSet, map[string]string{"sprout_id": "web-1", "name": "a", "value": "b"})
	inbox := nats.NewInbox()
	got, err := nc.SubscribeSync(inbox)
	if err != nil {
		t.Fatal(err)
	}
	m.Reply = inbox
	for range 2 { // the original, fanned out to both, then a replay
		if err := nc.PublishMsg(m); err != nil {
			t.Fatal(err)
		}
	}
	for range 4 {
		a, err := got.NextMsg(5 * time.Second)
		if err != nil {
			t.Fatalf("answers: %v (got %d)", err, len(answers))
		}
		answers = append(answers, a)
	}
	sealed := 0
	for _, a := range answers {
		switch {
		case a.Header.Get(payloadbox.Header) == payloadbox.HeaderBox1:
			sealed++
		case a.Header.Get(payloadbox.ErrorHeader) != payloadbox.ErrorCodeOpenFailed:
			t.Fatalf("answer %v", a.Header)
		}
	}
	if runs.Load() != 1 || sealed != 1 {
		t.Fatalf("ran %d times, %d sealed answers; want exactly one of each", runs.Load(), sealed)
	}
	if n := len(env.mr.Keys()); n != 1 {
		t.Errorf("%d claims in Valkey, want 1", n)
	}
}

// Valkey down: a mutating request is refused with a sealed error, a read
// runs.
func TestSealedRouterValkeyDown(t *testing.T) {
	f := startSealedFarmer(t)
	newSealedCLIUser(t)
	f.env.mr.SetError("LOADING Valkey is unavailable")
	if _, err := f.call(MethodPKIList, nil); err != nil {
		t.Fatalf("read with Valkey down: %v", err)
	}
	_, err := f.call(MethodPropsSet, map[string]string{"sprout_id": "web-1", "name": "a", "value": "b"})
	if err == nil || err.Error() != ErrSealedStoreUnavailable.Error() {
		t.Fatalf("mutating with Valkey down: %v, want the sealed ErrSealedStoreUnavailable", err)
	}
}

// auth.users.* with the key store: an admin adds a user with their box
// key, the new user can make requests at once, sees their key's
// fingerprint in auth.users, rotates it, and once removed (or reset) the
// old key opens nothing.
func TestSealedAuthUsersWithKeyStore(t *testing.T) {
	// Users and their keys belong to the users tenant (farmerorganization):
	// make it the tenant this farmer serves.
	origOrg := config.FarmerOrganization
	config.FarmerOrganization = "t_1"
	t.Cleanup(func() { config.FarmerOrganization = origOrg })
	f := startSealedFarmer(t)
	admin := newSealedCLIUser(t)

	// Bob runs imas auth keygen on his own host.
	bobKP, _ := nkeys.CreateAccount()
	bobSeed, _ := bobKP.Seed()
	bobID, _ := bobKP.PublicKey()
	bob := &cliUser{id: bobID, seed: bobSeed, tenant: "t_1", keyFile: t.TempDir() + "/bob.key"}
	bobPub, err := pki.GenerateCLIBoxKey(bob.keyFile, false)
	if err != nil {
		t.Fatal(err)
	}

	// Missing box key: refused, nothing registered.
	if _, err := f.call(MethodAuthAddUser, map[string]string{"pubkey": bobID, "role": "admin"}); err == nil {
		t.Fatal("a user was added without a box key")
	}
	if _, err := f.call(MethodAuthAddUser, map[string]string{"pubkey": bobID, "role": "admin", "username": "bob", "boxpub": bobPub}); err != nil {
		t.Fatalf("auth.users.add: %v", err)
	}
	res, err := f.call(MethodAuthListUsers, nil)
	if err != nil {
		t.Fatal(err)
	}
	var list UsersListResult
	if err := json.Unmarshal(res, &list); err != nil || list.Users[bobID] != "admin" || list.BoxKeys[bobID] != boxKeyFingerprint(bobPub) {
		t.Fatalf("auth.users: %+v, %v", list, err)
	}

	// Bob, from his CLI.
	bob.use(t)
	res, err = f.call(MethodAuthWhoAmI, nil)
	if err != nil {
		t.Fatalf("bob's whoami: %v", err)
	}
	var who apitypes.UserInfo
	_ = json.Unmarshal(res, &who)
	if who.Pubkey != bobID || who.Username != "bob" {
		t.Fatalf("bob is %+v", who)
	}

	// Bob loses his key; the admin resets it.
	admin.use(t)
	newPath := t.TempDir() + "/bob2.key"
	newPub, err := pki.GenerateCLIBoxKey(newPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.call(MethodAuthResetKey, map[string]string{"pubkey": bobID, "boxpub": newPub}); err != nil {
		t.Fatalf("auth.users.resetkey: %v", err)
	}
	bob.use(t)
	var refused *client.RefusedError
	if _, err := f.call(MethodAuthWhoAmI, nil); !errors.As(err, &refused) {
		t.Fatalf("bob's old key after a reset: %v", err)
	}
	jety.Set(pki.CLIBoxPrivFileKey, newPath)
	if _, err := f.call(MethodAuthWhoAmI, nil); err != nil {
		t.Fatalf("bob's new key: %v", err)
	}

	// Removed: the next request opens nothing.
	admin.use(t)
	if _, err := f.call(MethodAuthRemoveUser, map[string]string{"pubkey": bobID}); err != nil {
		t.Fatalf("auth.users.remove: %v", err)
	}
	bob.use(t)
	jety.Set(pki.CLIBoxPrivFileKey, newPath)
	if _, err := f.call(MethodAuthWhoAmI, nil); !errors.As(err, &refused) {
		t.Fatalf("a removed user: %v", err)
	}
}

// imas auth rotate-key against the real router: the reply opens only
// under the new key, which the CLI then promotes; the old key opens for
// the grace window.
func TestSealedRotateKeyThroughRouter(t *testing.T) {
	f := startSealedFarmer(t)
	u := newSealedCLIUser(t)
	before, err := pki.CLIBoxPub()
	if err != nil {
		t.Fatal(err)
	}
	data, id, principal, newPub, err := pki.BeginCLIBoxKeyRotation()
	if err != nil {
		t.Fatal(err)
	}
	m := nats.NewMsg(Subject(MethodAuthRotateKey))
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Header.Set(payloadbox.PrincipalHeader, principal)
	m.Data = data
	resp := f.raw(t, m)
	body, err := pki.CLIOpenReply(MethodAuthRotateKey, id, resp.Data)
	if err != nil || body.Error != "" {
		t.Fatalf("rotation reply %+v, %v", body, err)
	}
	if cur, _ := pki.CLIBoxPub(); cur != newPub || cur == before {
		t.Fatalf("CLI key %q, want the new key %q", cur, newPub)
	}
	active, grace, err := intauth.ValidCLIBoxKeys("t_1", u.id)
	if err != nil || active != newPub || len(grace) != 1 || grace[0] != before {
		t.Fatalf("farmer: active %q grace %v %v", active, grace, err)
	}
	if _, err := f.call(MethodAuthWhoAmI, nil); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
}

// Every request is audited as the verified user; params naming someone
// else change nothing.
func TestSealedRouterAudit(t *testing.T) {
	f := startSealedFarmer(t)
	u := newSealedCLIUser(t)
	dir := t.TempDir()
	logger, err := audit.NewLogger(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	audit.SetGlobal(logger)
	defer audit.SetGlobal(nil)
	audit.SetLevel(audit.LevelAll)
	defer audit.SetLevel(audit.LevelWrite)

	_, _ = f.call(MethodPropsSet, map[string]string{"sprout_id": "web-1", "name": "a", "value": "b", "token": "x", "pubkey": "USOMEONEELSE"})
	q, err := logger.Query(audit.QueryParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Entries) == 0 {
		t.Fatal("nothing audited")
	}
	e := q.Entries[len(q.Entries)-1]
	if e.Pubkey != u.id || e.Action != MethodPropsSet || e.RoleName != "admin" || len(e.Targets) != 1 || e.Targets[0] != "web-1" {
		t.Fatalf("audit entry %+v", e)
	}
}
