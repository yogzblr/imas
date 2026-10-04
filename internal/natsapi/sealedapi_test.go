package natsapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/taigrr/jety"
	"github.com/valkey-io/valkey-go"

	intauth "github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
	"github.com/yogzblr/imas/internal/rbac"
)

// sealedEnv is one test's farmer side: tenant keys in a mock OpenBao, a
// Valkey stand-in shared by every "replica", and an admin role.
type sealedEnv struct {
	bao *tenantboxtest.Server
	mr  *miniredis.Miniredis
}

func setupSealedEnv(t *testing.T) *sealedEnv {
	t.Helper()
	bao := tenantboxtest.Start(t)
	pki.InvalidateTenantBoxKeys("t_1")
	pki.InvalidatePlatformBoxKeys()
	t.Cleanup(func() { pki.InvalidateTenantBoxKeys("t_1"); pki.InvalidatePlatformBoxKeys() })

	mr := miniredis.RunT(t)
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	pki.SetReplayCacheClient(client)
	t.Cleanup(func() { pki.SetReplayCacheClient(nil) })

	rs := rbac.NewRoleStore()
	if err := rs.Register(&rbac.Role{Name: "admin", Rules: []rbac.Rule{{Action: rbac.ActionAdmin, Scope: "*"}}}); err != nil {
		t.Fatal(err)
	}
	intauth.SetPolicy(rs, rbac.NewUserRoleMap(), nil)
	t.Cleanup(func() { intauth.SetPolicy(nil, nil, nil) })
	return &sealedEnv{bao: bao, mr: mr}
}

// cliUser is a CLI user with a registered CLI box key in t_1, whose CLI
// config (jety) is loaded.
type cliUser struct {
	id, keyFile string
	seed        []byte
}

func newSealedCLIUser(t *testing.T) *cliUser {
	t.Helper()
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := kp.Seed()
	id, _ := kp.PublicKey()
	intauth.CurrentPolicy().Users.Set(id, "admin")
	u := &cliUser{id: id, seed: seed, keyFile: filepath.Join(t.TempDir(), "cli-box.key")}
	u.use(t)
	pub, err := pki.GenerateCLIBoxKey(u.keyFile, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.RegisterCLIBoxKey("t_1", id, pub); err != nil {
		t.Fatalf("RegisterCLIBoxKey: %v", err)
	}
	return u
}

func (u *cliUser) use(t *testing.T) {
	t.Helper()
	tk, err := pki.GetTenantX25519PublicKey("t_1")
	if err != nil {
		t.Fatal(err)
	}
	jety.Set("privkey", string(u.seed))
	jety.Set(pki.CLIBoxPrivFileKey, u.keyFile)
	jety.Set(pki.CLITenantBoxPubKey, tk)
	jety.Set(pki.CLITenantIDKey, "t_1")
	t.Cleanup(func() {
		for _, k := range []string{"privkey", pki.CLIBoxPrivFileKey, pki.CLITenantBoxPubKey, pki.CLITenantIDKey} {
			jety.Set(k, "")
		}
	})
}

// cliRequest is what the CLI puts on the bus for method: the sealed
// envelope with the payloadbox and principal headers.
func cliRequest(t *testing.T, method string, params any) (*nats.Msg, string) {
	t.Helper()
	purpose := payloadbox.PurposeCLIRequest
	if method == MethodAuthRotateKey {
		purpose = payloadbox.PurposeCLIUserKeySubmit
	}
	data, id, principal, err := pki.CLISealRequest(purpose, method, params)
	if err != nil {
		t.Fatal(err)
	}
	m := nats.NewMsg(Subject(method))
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Header.Set(payloadbox.PrincipalHeader, principal)
	m.Data = data
	return m, id
}

func wantCode(t *testing.T, name string, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: accepted, want refusal %s", name, code)
	}
	if got := RefusalCode(err); got != code {
		t.Fatalf("%s: code %s (%v), want %s", name, got, err, code)
	}
}

// A read and a mutating request each open on farmer, and the sealed
// reply, result or error, opens on the CLI.
func TestSealedCLIRequestAndReply(t *testing.T) {
	setupSealedEnv(t)
	newSealedCLIUser(t)
	replica := newSealedAPI()
	for _, method := range []string{MethodJobsList, MethodJobsDelete} {
		m, id := cliRequest(t, method, map[string]string{"jid": "j-1"})
		req, err := replica.openCLIRequest(t.Context(), "t_1", m)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		if req.ID != id || req.Method != method || string(req.Params) != `{"jid":"j-1"}` {
			t.Fatalf("%s: %+v", method, req)
		}
		for _, tc := range []struct {
			result any
			err    error
		}{{[]string{"ok"}, nil}, {nil, errors.New("job not found")}} {
			reply, err := sealCLIReply(req, tc.result, tc.err)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(reply, []byte("job not found")) {
				t.Fatal("a handler error is readable on the wire")
			}
			body, err := pki.CLIOpenReply(method, id, reply)
			if err != nil {
				t.Fatalf("%s: CLIOpenReply: %v", method, err)
			}
			if tc.err != nil && body.Error != tc.err.Error() || tc.err == nil && string(body.Result) != `["ok"]` {
				t.Fatalf("%s: reply %+v", method, body)
			}
		}
	}
}

func TestSealedCLIRequestRefusals(t *testing.T) {
	setupSealedEnv(t)
	bob := newSealedCLIUser(t)
	newSealedCLIUser(t) // alice, the current CLI
	replica := newSealedAPI()

	m, _ := cliRequest(t, MethodJobsList, nil)
	plain := nats.NewMsg(m.Subject)
	plain.Data = []byte(`{"token":"x"}`)
	_, err := replica.openCLIRequest(t.Context(), "t_1", plain)
	wantCode(t, "plaintext", err, payloadbox.ErrorCodeEncryptionRequired)

	noPrincipal := nats.NewMsg(m.Subject)
	noPrincipal.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	noPrincipal.Data = m.Data
	_, err = replica.openCLIRequest(t.Context(), "t_1", noPrincipal)
	wantCode(t, "no principal", err, payloadbox.ErrorCodeOpenFailed)

	// Wrong principal: the header names bob, the request is alice's.
	asBob := nats.NewMsg(m.Subject)
	asBob.Header = nats.Header(http.Header(m.Header).Clone())
	asBob.Header.Set(payloadbox.PrincipalHeader, bob.id)
	asBob.Data = m.Data
	_, err = replica.openCLIRequest(t.Context(), "t_1", asBob)
	wantCode(t, "wrong principal", err, payloadbox.ErrorCodeOpenFailed)

	// Wrong method and subject: a sealed jobs.list moved onto jobs.delete.
	moved := nats.NewMsg(Subject(MethodJobsDelete))
	moved.Header = m.Header
	moved.Data = m.Data
	_, err = replica.openCLIRequest(t.Context(), "t_1", moved)
	wantCode(t, "wrong subject", err, payloadbox.ErrorCodeOpenFailed)

	// Another tenant's connection.
	_, err = replica.openCLIRequest(t.Context(), "t_2", m)
	wantCode(t, "wrong tenant", err, payloadbox.ErrorCodeOpenFailed)

	// None of those refusals used up the genuine request.
	if _, err := replica.openCLIRequest(t.Context(), "t_1", m); err != nil {
		t.Fatalf("the genuine request after the refusals: %v", err)
	}
}

// staleCLIRequest seals a request for the current CLI user issued ten
// minutes ago, as a bus holding a captured request would replay it.
func staleCLIRequest(t *testing.T, u *cliUser, method string) *nats.Msg {
	t.Helper()
	raw, err := os.ReadFile(u.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	privBytes, _ := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(raw)))
	var priv [32]byte
	copy(priv[:], privBytes)
	tk, _ := pki.TenantBoxKeys("t_1")
	id, _ := payloadbox.NewID()
	body, _ := json.Marshal(payloadbox.CallBody{Method: method, Subject: Subject(method)})
	data, err := payloadbox.Seal(payloadbox.Message{
		V: payloadbox.Version, Purpose: payloadbox.PurposeCLIRequest, TenantID: "t_1", SproutID: u.id,
		ID: id, IssuedAt: time.Now().Add(-10 * time.Minute).Unix(), Body: body,
	}, []payloadbox.KeyPair{{PeerPub: tk[0].Pub, Priv: &priv}})
	if err != nil {
		t.Fatal(err)
	}
	m := nats.NewMsg(Subject(method))
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Header.Set(payloadbox.PrincipalHeader, u.id)
	m.Data = data
	return m
}

func TestSealedCLIRequestStale(t *testing.T) {
	setupSealedEnv(t)
	u := newSealedCLIUser(t)
	_, err := newSealedAPI().openCLIRequest(t.Context(), "t_1", staleCLIRequest(t, u, MethodJobsList))
	wantCode(t, "stale", err, payloadbox.ErrorCodeOpenFailed)
	if !errors.Is(err, payloadbox.ErrStale) {
		t.Fatalf("stale: %v, want ErrStale", err)
	}
}

// Replayed on one replica: refused whatever the method. Replayed on
// another replica: a mutating request is refused by its Valkey claim; a
// read runs again (its reply is sealed to the requester).
func TestSealedCLIRequestReplays(t *testing.T) {
	env := setupSealedEnv(t)
	newSealedCLIUser(t)
	replicaA, replicaB := newSealedAPI(), newSealedAPI()

	for _, method := range []string{MethodJobsList, MethodJobsDelete} {
		m, _ := cliRequest(t, method, nil)
		if _, err := replicaA.openCLIRequest(t.Context(), "t_1", m); err != nil {
			t.Fatalf("%s first: %v", method, err)
		}
		_, err := replicaA.openCLIRequest(t.Context(), "t_1", m)
		wantCode(t, method+" replayed on the same replica", err, payloadbox.ErrorCodeOpenFailed)
		if !errors.Is(err, payloadbox.ErrReplayed) {
			t.Fatalf("%s: %v, want ErrReplayed", method, err)
		}
		_, err = replicaB.openCLIRequest(t.Context(), "t_1", m)
		if IsMutatingMethod(method) {
			wantCode(t, method+" replayed on another replica", err, payloadbox.ErrorCodeOpenFailed)
			if !errors.Is(err, pki.ErrSealedReplayed) {
				t.Fatalf("%s: %v, want ErrSealedReplayed", method, err)
			}
		} else if err != nil {
			t.Fatalf("read replayed on another replica: %v (expected to run; its reply is sealed)", err)
		}
	}
	// The mutating request's claim is keyed on (tenant, user, id).
	if n := len(env.mr.Keys()); n != 1 {
		t.Errorf("claims in Valkey: %d, want 1 (reads never claim)", n)
	}
}

// Valkey down: mutating requests are refused (fail closed), reads run.
func TestSealedCLIRequestValkeyDown(t *testing.T) {
	env := setupSealedEnv(t)
	newSealedCLIUser(t)
	replica := newSealedAPI()
	env.mr.SetError("LOADING Valkey is unavailable")

	read, _ := cliRequest(t, MethodJobsList, nil)
	if _, err := replica.openCLIRequest(t.Context(), "t_1", read); err != nil {
		t.Fatalf("read with Valkey down: %v", err)
	}
	for _, method := range []string{MethodJobsDelete, MethodCohortsRefresh, MethodAuthAddUser, "some.future.method"} {
		m, id := cliRequest(t, method, nil)
		_, err := replica.openCLIRequest(t.Context(), "t_1", m)
		if !errors.Is(err, ErrSealedStoreUnavailable) {
			t.Fatalf("%s with Valkey down: %v, want ErrSealedStoreUnavailable", method, err)
		}
		// The request opened, so the refusal goes back sealed.
		req := &sealedRequest{TenantID: "t_1", Principal: jetyUser(t), Method: method, Subject: Subject(method), ID: id}
		reply, err := sealCLIReply(req, nil, err)
		if err != nil {
			t.Fatal(err)
		}
		if body, err := pki.CLIOpenReply(method, id, reply); err != nil || body.Error == "" {
			t.Fatalf("%s: sealed refusal %+v, %v", method, body, err)
		}
	}
	// No client at all fails closed too.
	pki.SetReplayCacheClient(nil)
	m, _ := cliRequest(t, MethodJobsDelete, nil)
	if _, err := replica.openCLIRequest(t.Context(), "t_1", m); !errors.Is(err, ErrSealedStoreUnavailable) {
		t.Fatalf("no Valkey client: %v", err)
	}
}

func jetyUser(t *testing.T) string {
	t.Helper()
	id, err := intauth.GetPubkey()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// The read-only list is the design's, every entry is a real method, and
// anything else (cohorts.refresh, the auth.users mutators, methods added
// later) counts as mutating.
func TestReadOnlyMethods(t *testing.T) {
	for m := range readOnlyMethods {
		if _, ok := routes[m]; !ok {
			t.Errorf("read-only method %q is not a route", m)
		}
	}
	if len(readOnlyMethods) != 19 {
		t.Errorf("%d read-only methods, the design lists 19", len(readOnlyMethods))
	}
	for _, m := range []string{MethodCohortsRefresh, MethodAuthAddUser, MethodAuthRemoveUser, MethodAuthLogin,
		MethodCmdRun, MethodCook, MethodShellStart, MethodPKIRotateTenantBoxKey, MethodAuthRotateKey, "x.y"} {
		if !IsMutatingMethod(m) {
			t.Errorf("%s is not treated as mutating", m)
		}
	}
	for _, m := range []string{MethodJobsList, MethodAuditQuery, MethodPKIList} {
		if IsMutatingMethod(m) {
			t.Errorf("%s is treated as mutating", m)
		}
	}
}

// The guard is keyed on (tenant, principal, id): the same message ID from
// another principal or tenant is a different message.
func TestAPIReplayGuardKeying(t *testing.T) {
	g := newAPIReplayGuard()
	id, _ := payloadbox.NewID()
	msg := &payloadbox.Message{ID: id, IssuedAt: time.Now().Unix()}
	for _, k := range [][2]string{{"t_1", "UA"}, {"t_1", "UB"}, {"t_2", "UA"}, {"t_1U", "A"}} {
		if err := g.Accept(k[0], k[1], msg); err != nil {
			t.Fatalf("%v: %v", k, err)
		}
	}
	if err := g.Accept("t_1", "UA", msg); !errors.Is(err, payloadbox.ErrReplayed) {
		t.Fatalf("replay: %v", err)
	}
	if msg.ID != id {
		t.Fatal("the guard changed the caller's message")
	}
}

// The whole CLI path on a real bus, wired by these helpers alone (the
// router is untouched): the CLI's sealed request, farmer's sealed reply,
// a replay answered with the fixed code, a plaintext request refused.
func TestSealedCLIOverTheBus(t *testing.T) {
	setupSealedEnv(t)
	newSealedCLIUser(t)
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	replica := newSealedAPI()
	sub, err := nc.Subscribe(Subject(MethodJobsList), func(m *nats.Msg) {
		req, err := replica.openCLIRequest(context.Background(), "t_1", m)
		if err != nil {
			_ = respondSealedRefusal(m, err)
			return
		}
		reply, err := sealCLIReply(req, map[string]int{"count": 3}, nil)
		if err != nil {
			_ = respondSealedRefusal(m, err)
			return
		}
		_ = respondSealed(m, reply)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()

	m, id := cliRequest(t, MethodJobsList, nil)
	resp, err := nc.RequestMsg(m, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		t.Fatalf("reply headers %v", resp.Header)
	}
	body, err := pki.CLIOpenReply(MethodJobsList, id, resp.Data)
	if err != nil || string(body.Result) != `{"count":3}` {
		t.Fatalf("reply %+v, %v", body, err)
	}
	m.Reply = ""
	resp, err = nc.RequestMsg(m, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get(payloadbox.ErrorHeader) != payloadbox.ErrorCodeOpenFailed || len(resp.Data) != 0 {
		t.Fatalf("replay answered %v %q", resp.Header, resp.Data)
	}
	plain := nats.NewMsg(Subject(MethodJobsList))
	plain.Data = []byte(`{}`)
	resp, err = nc.RequestMsg(plain, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get(payloadbox.ErrorHeader) != payloadbox.ErrorCodeEncryptionRequired {
		t.Fatalf("plaintext answered %v", resp.Header)
	}
	if replicaSealedAPI == nil {
		t.Fatal("no replica state")
	}
}

// ---- SaaS API --------------------------------------------------------------

func setupSaaSAPIKeys(t *testing.T, env *sealedEnv) *pki.SaaSAPIBox {
	t.Helper()
	t.Setenv(pki.EnvCPBoxOpenBaoAddr, env.bao.URL)
	t.Setenv(pki.EnvCPBoxOpenBaoAuthMethod, "token")
	t.Setenv(pki.EnvCPBoxOpenBaoToken, tenantboxtest.Token)
	t.Setenv(pki.EnvCPBoxOpenBaoKVPath, tenantboxtest.BasePath)
	if _, err := pki.EnsureControlPlaneBoxKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	saas := env.bao.Versions(tenantboxtest.BasePath + "/saasapi-box")[0].Data
	pubs := env.bao.Versions(tenantboxtest.BasePath + "/controlplane-pub")[0].Data
	privFile := filepath.Join(t.TempDir(), "saasapi-box.key")
	if err := os.WriteFile(privFile, []byte(saas["priv"]), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := pki.LoadSaaSAPIBox(privFile, pubs["platform_pub"])
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func saasRequest(t *testing.T, b *pki.SaaSAPIBox, subject string) (*nats.Msg, string) {
	t.Helper()
	data, id, err := b.SealRequest(saasapiPurposes[subject], subject[len(saasapiSubjectPrefix):], subject, map[string]string{"tenant_id": "t_1"})
	if err != nil {
		t.Fatal(err)
	}
	m := nats.NewMsg(subject)
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Header.Set(payloadbox.PrincipalHeader, payloadbox.PrincipalSaaSAPI)
	m.Data = data
	return m, id
}

func TestSealedSaaSAPIRequests(t *testing.T) {
	env := setupSealedEnv(t)
	saas := setupSaaSAPIKeys(t, env)
	replicaA, replicaB := newSealedAPI(), newSealedAPI()
	for _, subject := range []string{controlplane.SubjectTenantProvision, controlplane.SubjectTenantDeprovision, controlplane.SubjectSproutAction} {
		m, id := saasRequest(t, saas, subject)
		req, err := replicaA.openSaaSAPIRequest(t.Context(), m)
		if err != nil {
			t.Fatalf("%s: %v", subject, err)
		}
		if req.ID != id || string(req.Params) != `{"tenant_id":"t_1"}` {
			t.Fatalf("%s: %+v", subject, req)
		}
		_, err = replicaA.openSaaSAPIRequest(t.Context(), m)
		wantCode(t, subject+" replayed on the same replica", err, payloadbox.ErrorCodeOpenFailed)
		_, err = replicaB.openSaaSAPIRequest(t.Context(), m)
		wantCode(t, subject+" replayed on another replica", err, payloadbox.ErrorCodeOpenFailed)
		if subject != controlplane.SubjectSproutAction {
			continue
		}
		reply, err := sealSaaSAPIReply(req, map[string]string{"status": "dispatched"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := saas.OpenReply(payloadbox.PurposeSaaSSproutActionReply, req.Method, subject, id, reply)
		if err != nil || string(body.Result) != `{"status":"dispatched"}` {
			t.Fatalf("reply %+v, %v", body, err)
		}
	}
	for _, deprovision := range []bool{false, true} {
		subject, data, err := sealSaaSAPIResult(deprovision, "job-42", map[string]string{"job_id": "job-42", "tenant_id": "t_1"})
		if err != nil {
			t.Fatal(err)
		}
		purpose, method := payloadbox.PurposeSaaSTenantProvisioned, "tenant.provisioned"
		if deprovision {
			purpose, method = payloadbox.PurposeSaaSTenantDeprovisioned, "tenant.deprovisioned"
		}
		if subject != "internal."+method+".job-42" {
			t.Fatalf("subject %s", subject)
		}
		if _, err := saas.OpenResult(purpose, method, subject, data); err != nil {
			t.Fatalf("%s: OpenResult: %v", subject, err)
		}
	}
	if _, _, err := sealSaaSAPIResult(false, "job.42", nil); err == nil {
		t.Error("a job id with a dot made a subject")
	}
}

func TestSealedSaaSAPIRefusals(t *testing.T) {
	env := setupSealedEnv(t)
	saas := setupSaaSAPIKeys(t, env)
	replica := newSealedAPI()

	m, _ := saasRequest(t, saas, controlplane.SubjectSproutAction)
	asUser := nats.NewMsg(m.Subject)
	asUser.Header = nats.Header(http.Header(m.Header).Clone())
	asUser.Header.Set(payloadbox.PrincipalHeader, "AUSER")
	asUser.Data = m.Data
	_, err := replica.openSaaSAPIRequest(t.Context(), asUser)
	wantCode(t, "wrong principal", err, payloadbox.ErrorCodeOpenFailed)

	moved := nats.NewMsg(controlplane.SubjectTenantDeprovision)
	moved.Header = m.Header
	moved.Data = m.Data
	_, err = replica.openSaaSAPIRequest(t.Context(), moved)
	wantCode(t, "wrong subject", err, payloadbox.ErrorCodeOpenFailed)

	plain := nats.NewMsg(m.Subject)
	plain.Data = []byte(`{"tenant_id":"t_1"}`)
	_, err = replica.openSaaSAPIRequest(t.Context(), plain)
	wantCode(t, "plaintext", err, payloadbox.ErrorCodeEncryptionRequired)

	env.mr.SetError("down")
	if _, err := replica.openSaaSAPIRequest(t.Context(), m); !errors.Is(err, ErrSealedStoreUnavailable) {
		t.Fatalf("Valkey down: %v, want ErrSealedStoreUnavailable", err)
	}
}

func TestSealedSaaSAPIWithoutPlatformKey(t *testing.T) {
	setupSealedEnv(t)
	m := nats.NewMsg(controlplane.SubjectSproutAction)
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Header.Set(payloadbox.PrincipalHeader, payloadbox.PrincipalSaaSAPI)
	m.Data = []byte(`{"v":2,"s":[]}`)
	_, err := newSealedAPI().openSaaSAPIRequest(t.Context(), m)
	wantCode(t, "no platform key", err, payloadbox.ErrorCodeNoKeys)
}
