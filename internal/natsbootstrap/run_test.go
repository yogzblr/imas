package natsbootstrap

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/natskeys"
	"github.com/yogzblr/imas/internal/pki/natskeys/natskeystest"
)

const (
	testNamespace = "imas"
	testSAToken   = "kube-sa-token"
)

// fakeKube is the part of the Kubernetes API the command uses: the
// ConfigMaps of one namespace.
type fakeKube struct {
	mu        sync.Mutex
	cms       map[string]*configMap
	rv        int
	writes    int // successful creates and updates
	conflicts int // 409s still to inject on the next writes
	getErr    int // status to answer every GET with, 0 for none
}

func (k *fakeKube) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+testSAToken {
		kubeStatus(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	base := "/api/v1/namespaces/" + testNamespace + "/configmaps"
	name, named := strings.CutPrefix(r.URL.Path, base+"/")
	if !named && r.URL.Path != base {
		kubeStatus(w, http.StatusNotFound, "no route")
		return
	}
	switch {
	case r.Method == http.MethodGet && named:
		if k.getErr != 0 {
			kubeStatus(w, k.getErr, "injected")
			return
		}
		cm := k.cms[name]
		if cm == nil {
			kubeStatus(w, http.StatusNotFound, "configmaps \""+name+"\" not found")
			return
		}
		json.NewEncoder(w).Encode(cm)
	case (r.Method == http.MethodPost && !named) || (r.Method == http.MethodPut && named):
		var cm configMap
		if err := json.NewDecoder(r.Body).Decode(&cm); err != nil {
			kubeStatus(w, http.StatusBadRequest, err.Error())
			return
		}
		if k.conflicts > 0 {
			k.conflicts--
			kubeStatus(w, http.StatusConflict, "injected conflict")
			return
		}
		n := metaName(&cm)
		cur := k.cms[n]
		if r.Method == http.MethodPost && cur != nil {
			kubeStatus(w, http.StatusConflict, "already exists")
			return
		}
		if r.Method == http.MethodPut {
			if n != name || cur == nil {
				kubeStatus(w, http.StatusNotFound, "not found")
				return
			}
			if cm.Metadata["resourceVersion"] != cur.Metadata["resourceVersion"] {
				kubeStatus(w, http.StatusConflict, "the object has been modified")
				return
			}
		}
		k.rv++
		cm.Metadata["resourceVersion"] = strconv.Itoa(k.rv)
		k.cms[n] = &cm
		k.writes++
		json.NewEncoder(w).Encode(&cm)
	default:
		kubeStatus(w, http.StatusMethodNotAllowed, "unsupported")
	}
}

func kubeStatus(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "code": code, "message": msg})
}

// data returns a copy of name's data, nil when it does not exist.
func (k *fakeKube) data(name string) map[string]string {
	k.mu.Lock()
	defer k.mu.Unlock()
	if cm := k.cms[name]; cm != nil {
		return maps.Clone(cm.Data)
	}
	return nil
}

func (k *fakeKube) put(name string, data map[string]string, meta map[string]any) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.rv++
	m := map[string]any{"name": name, "namespace": testNamespace, "resourceVersion": strconv.Itoa(k.rv)}
	maps.Copy(m, meta)
	k.cms[name] = &configMap{APIVersion: "v1", Kind: "ConfigMap", Metadata: m, Data: data}
}

func (k *fakeKube) writeCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.writes
}

// openBaoFront serves auth/token/revoke-self and a KV v2 mount "secret"
// itself and passes everything else to the fake Transit.
type openBaoFront struct {
	mu       sync.Mutex
	revoked  []string // tokens revoked
	kv       map[string]map[string]any
	kvWrites int
}

func (o *openBaoFront) handler(transit *natskeystest.Fake) http.Handler {
	u, _ := url.Parse(transit.URL)
	proxy := httputil.NewSingleHostReverseProxy(u)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Vault-Token")
		if r.URL.Path == "/v1/auth/token/revoke-self" && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
			o.mu.Lock()
			o.revoked = append(o.revoked, tok)
			o.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if p, ok := strings.CutPrefix(r.URL.Path, "/v1/secret/data/"); ok {
			o.mu.Lock()
			defer o.mu.Unlock()
			if tok != natskeystest.Token {
				w.WriteHeader(http.StatusForbidden)
				io.WriteString(w, `{"errors":["permission denied"]}`)
				return
			}
			switch r.Method {
			case http.MethodGet:
				d, ok := o.kv[p]
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					io.WriteString(w, `{"errors":[]}`)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": d, "metadata": map[string]any{"version": 1}}})
			case http.MethodPut, http.MethodPost:
				var body struct {
					Data map[string]any `json:"data"`
				}
				json.NewDecoder(r.Body).Decode(&body)
				o.kv[p] = body.Data
				o.kvWrites++
				json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": 1}})
			}
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

func (o *openBaoFront) revokedTokens() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.revoked...)
}

type env struct {
	transit   *natskeystest.Fake
	front     *openBaoFront
	kube      *fakeKube
	tokenFile string
}

// setup starts the fakes and points the command's environment at them.
// It writes a token file unless noToken.
func setup(t *testing.T) *env {
	t.Helper()
	e := &env{
		transit: natskeystest.New(t),
		front:   &openBaoFront{kv: map[string]map[string]any{}},
		kube:    &fakeKube{cms: map[string]*configMap{}},
	}
	obSrv := httptest.NewServer(e.front.handler(e.transit))
	t.Cleanup(obSrv.Close)
	kubeSrv := httptest.NewTLSServer(e.kube)
	t.Cleanup(kubeSrv.Close)

	dir := t.TempDir()
	sa := filepath.Join(dir, "sa")
	if err := os.Mkdir(sa, 0o700); err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: kubeSrv.Certificate().Raw})
	for name, content := range map[string][]byte{
		"token":     []byte(testSAToken + "\n"),
		"ca.crt":    caPEM,
		"namespace": []byte(testNamespace),
	} {
		if err := os.WriteFile(filepath.Join(sa, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := serviceAccountDir
	serviceAccountDir = sa
	t.Cleanup(func() { serviceAccountDir = old })
	ku, _ := url.Parse(kubeSrv.URL)
	t.Setenv("KUBERNETES_SERVICE_HOST", ku.Hostname())
	t.Setenv("KUBERNETES_SERVICE_PORT", ku.Port())

	p := natskeys.EnvPrefixBoot
	t.Setenv(p+natskeys.EnvOpenBaoAddr, obSrv.URL)
	t.Setenv(p+natskeys.EnvOpenBaoAuthMethod, "token")
	t.Setenv(p+natskeys.EnvOpenBaoToken, "")
	t.Setenv(p+natskeys.EnvOpenBaoTransitMount, "transit")
	e.tokenFile = filepath.Join(dir, "handoff-token")
	t.Setenv(EnvTokenFile, e.tokenFile)
	for _, v := range []string{EnvTrustConfigMap, EnvOperatorName, EnvBusFenceUserPub, EnvBusLoaderUserPub, EnvKVCopy, EnvKVMount, EnvKVPath} {
		t.Setenv(v, "")
	}
	return e
}

func (e *env) writeToken(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(e.tokenFile, []byte(natskeystest.Token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runCmd(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var stderr bytes.Buffer
	code := Run(args, &stderr)
	return code, stderr.String()
}

func mustRun(t *testing.T) string {
	t.Helper()
	code, out := runCmd(t)
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, out)
	}
	return out
}

// verifyStore is a farmer-like store over the fake, for checking output.
func verifyStore(t *testing.T, e *env) natskeys.KeyStore {
	t.Helper()
	e.transit.SetEnv(t, natskeys.EnvPrefixSign)
	cfg, err := natskeys.ConfigFromEnv(natskeys.EnvPrefixSign, os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := natskeys.NewTransitKeyStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ks.Close() })
	return ks
}

func toBytes(m map[string]string) map[string][]byte {
	return bytesMap(m)
}

func newUserPub(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	return pub
}

func TestRunFirstCreatesConfigMap(t *testing.T) {
	e := setup(t)
	fence := newUserPub(t)
	t.Setenv(EnvBusFenceUserPub, fence)
	e.writeToken(t)
	mustRun(t)

	for _, k := range platformKeys {
		if !e.transit.Has(k.name) {
			t.Errorf("transit key %s not created", k.name)
		}
	}
	if n := e.transit.Count(natskeystest.OpCreateKey); n != 3 {
		t.Errorf("%d key creates, want 3", n)
	}
	data := e.kube.data(DefaultTrustConfigMap)
	if data == nil {
		t.Fatal("trust configmap not created")
	}
	trust, err := pki.ParseNATSTrust(toBytes(data))
	if err != nil {
		t.Fatalf("ParseNATSTrust: %v", err)
	}
	if trust.BusFenceUserJWT == "" {
		t.Error("no fence user JWT although a fence user was given")
	}
	if err := trust.VerifyAgainst(t.Context(), verifyStore(t, e)); err != nil {
		t.Fatalf("VerifyAgainst: %v", err)
	}
	if got := e.front.revokedTokens(); len(got) != 1 || got[0] != natskeystest.Token {
		t.Errorf("revoked tokens %v, want the bootstrap token once", got)
	}
	if _, err := os.Stat(e.tokenFile); !os.IsNotExist(err) {
		t.Errorf("token file still present (stat err %v)", err)
	}
}

// sharedUserPub is a valid user public key for a usage-error case.
var sharedUserPub = func() string {
	kp, err := nkeys.CreateUser()
	if err != nil {
		panic(err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		panic(err)
	}
	return pub
}()

// The loader's SYS user JWT is minted by the bootstrap, like the fence
// user's (issue #197 decision 6), and lands in the trust ConfigMap.
func TestRunMintsLoaderUser(t *testing.T) {
	e := setup(t)
	loader := newUserPub(t)
	t.Setenv(EnvBusFenceUserPub, newUserPub(t))
	t.Setenv(EnvBusLoaderUserPub, loader)
	e.writeToken(t)
	mustRun(t)
	data := e.kube.data(DefaultTrustConfigMap)
	trust, err := pki.ParseNATSTrust(toBytes(data))
	if err != nil {
		t.Fatalf("ParseNATSTrust: %v", err)
	}
	uc, err := jwt.DecodeUserClaims(trust.BusLoaderUserJWT)
	if err != nil {
		t.Fatalf("loader user jwt: %v", err)
	}
	if uc.Subject != loader || uc.Issuer != trust.SysAccountPub {
		t.Errorf("loader jwt sub/iss = %s/%s", uc.Subject, uc.Issuer)
	}
	if !uc.Pub.Allow.Contains("$SYS.REQ.ACCOUNT.*.CLAIMS.LOOKUP") || uc.Pub.Allow.Contains(">") {
		t.Errorf("loader permissions = %+v", uc.Permissions)
	}

	// A second run over its own output writes nothing.
	writes := e.kube.writeCount()
	e.writeToken(t)
	mustRun(t)
	if e.kube.writeCount() != writes {
		t.Error("second run rewrote the configmap")
	}
	if got := e.kube.data(DefaultTrustConfigMap)[pki.TrustBusLoaderUserJWT]; got != data[pki.TrustBusLoaderUserJWT] {
		t.Error("second run changed the loader jwt")
	}
}

func TestRunIdempotent(t *testing.T) {
	e := setup(t)
	t.Setenv(EnvBusFenceUserPub, newUserPub(t))
	e.writeToken(t)
	mustRun(t)
	first := e.kube.data(DefaultTrustConfigMap)
	writes := e.kube.writeCount()
	e.transit.ResetCounts()

	e.writeToken(t)
	out := mustRun(t)
	if n := e.transit.Count(natskeystest.OpCreateKey); n != 0 {
		t.Errorf("second run created %d keys", n)
	}
	if n := e.transit.Count(natskeystest.OpSign); n != 0 {
		t.Errorf("second run signed %d times", n)
	}
	if n := e.kube.writeCount(); n != writes {
		t.Errorf("second run wrote the configmap (%d writes, was %d)", n, writes)
	}
	if !maps.Equal(first, e.kube.data(DefaultTrustConfigMap)) {
		t.Error("configmap data changed on the second run")
	}
	if !strings.Contains(out, "nothing written") {
		t.Errorf("output does not say nothing was written:\n%s", out)
	}
}

func TestRunKeepsOtherDataAndMetadata(t *testing.T) {
	e := setup(t)
	e.kube.put(DefaultTrustConfigMap, map[string]string{"extra": "kept"}, map[string]any{"labels": map[string]any{"team": "platform"}})
	e.writeToken(t)
	mustRun(t)
	e.kube.mu.Lock()
	cm := e.kube.cms[DefaultTrustConfigMap]
	e.kube.mu.Unlock()
	if cm.Data["extra"] != "kept" {
		t.Error("unrelated configmap key dropped")
	}
	if l, _ := cm.Metadata["labels"].(map[string]any); l["team"] != "platform" {
		t.Errorf("labels lost: %v", cm.Metadata["labels"])
	}
	if _, err := pki.ParseNATSTrust(toBytes(cm.Data)); err != nil {
		t.Fatal(err)
	}
}

func TestRunRefusesChangedAnchor(t *testing.T) {
	e := setup(t)
	e.writeToken(t)
	mustRun(t)
	before := e.kube.data(DefaultTrustConfigMap)
	writes := e.kube.writeCount()
	// The operator identity key is replaced in Transit: the existing
	// anchor no longer matches and must not be overwritten.
	e.transit.Delete(natskeys.OperatorKey())

	e.writeToken(t)
	code, out := runCmd(t)
	if code != 1 {
		t.Fatalf("exit %d, want 1; output:\n%s", code, out)
	}
	if !strings.Contains(out, "would change") {
		t.Errorf("output does not name the changed anchor:\n%s", out)
	}
	if e.kube.writeCount() != writes || !maps.Equal(before, e.kube.data(DefaultTrustConfigMap)) {
		t.Error("configmap written although the anchor would change")
	}
	if n := len(e.front.revokedTokens()); n != 2 {
		t.Errorf("%d revocations, want 2 (the failed run revokes too)", n)
	}
}

func TestRunNoTokenCompleteConfigMap(t *testing.T) {
	e := setup(t)
	e.writeToken(t)
	mustRun(t)
	writes := e.kube.writeCount()
	e.transit.ResetCounts()

	// No token file, no OpenBao credential: the ConfigMap alone decides.
	out := mustRun(t)
	if !strings.Contains(out, "not compared with Transit") {
		t.Errorf("output:\n%s", out)
	}
	if e.transit.Count(natskeystest.OpReadKey) != 0 {
		t.Error("contacted Transit without a credential")
	}

	// With a credential configured, it compares with Transit.
	t.Setenv(natskeys.EnvPrefixBoot+natskeys.EnvOpenBaoToken, natskeystest.Token)
	out = mustRun(t)
	if !strings.Contains(out, "matches Transit") {
		t.Errorf("output:\n%s", out)
	}
	if e.transit.Count(natskeystest.OpCreateKey) != 0 || e.kube.writeCount() != writes {
		t.Error("check mode created a key or wrote the configmap")
	}
	if n := len(e.front.revokedTokens()); n != 1 {
		t.Errorf("check mode revoked a token (%d revocations)", n)
	}

	// A mismatch with Transit fails.
	e.transit.Delete(natskeys.SysAccountKey())
	e.transit.NewKey(natskeys.SysAccountKey())
	if code, out := runCmd(t); code != 1 || !strings.Contains(out, "does not match") {
		t.Errorf("exit %d on a mismatch, want 1; output:\n%s", code, out)
	}
}

func TestRunNoTokenIncompleteFails(t *testing.T) {
	e := setup(t)
	if code, out := runCmd(t); code != 1 || !strings.Contains(out, "does not exist") {
		t.Errorf("missing configmap: exit %d, want 1; output:\n%s", code, out)
	}
	e.writeToken(t)
	mustRun(t)
	data := e.kube.data(DefaultTrustConfigMap)
	delete(data, pki.TrustSysAccountJWT)
	e.kube.put(DefaultTrustConfigMap, data, nil)
	if code, out := runCmd(t); code != 1 || !strings.Contains(out, "incomplete") {
		t.Errorf("incomplete configmap: exit %d, want 1; output:\n%s", code, out)
	}
	if e.transit.Count(natskeystest.OpCreateKey) != 3 {
		t.Error("check mode created keys")
	}
}

func TestRunSelfRevokesToken(t *testing.T) {
	e := setup(t)
	e.writeToken(t)
	mustRun(t)
	if got := e.front.revokedTokens(); len(got) != 1 || got[0] != natskeystest.Token {
		t.Fatalf("revoked %v", got)
	}

	// A run that fails part way still revokes and removes the file.
	e.kube.mu.Lock()
	e.kube.getErr = http.StatusInternalServerError
	e.kube.mu.Unlock()
	e.writeToken(t)
	if code, out := runCmd(t); code != 1 {
		t.Fatalf("exit %d, want 1; output:\n%s", code, out)
	}
	if n := len(e.front.revokedTokens()); n != 2 {
		t.Errorf("failed run did not revoke (%d revocations)", n)
	}
	if _, err := os.Stat(e.tokenFile); !os.IsNotExist(err) {
		t.Errorf("token file still present after a failed run (stat err %v)", err)
	}
}

func TestConfigMapConflictRetry(t *testing.T) {
	e := setup(t)
	e.kube.conflicts = conflictRetries
	e.writeToken(t)
	mustRun(t)
	if _, err := pki.ParseNATSTrust(toBytes(e.kube.data(DefaultTrustConfigMap))); err != nil {
		t.Fatalf("after %d conflicts: %v", conflictRetries, err)
	}

	// One conflict more than the retries fails.
	e2 := setup(t)
	e2.kube.conflicts = conflictRetries + 1
	e2.writeToken(t)
	if code, out := runCmd(t); code != 1 || !strings.Contains(out, "409") {
		t.Errorf("exit %d, want 1; output:\n%s", code, out)
	}
	if e2.kube.data(DefaultTrustConfigMap) != nil {
		t.Error("configmap written despite persistent conflicts")
	}
}

func TestRunKVCopy(t *testing.T) {
	e := setup(t)
	t.Setenv(EnvKVCopy, "true")
	e.writeToken(t)
	mustRun(t)
	got := e.front.kv[DefaultKVPath]
	if got == nil {
		t.Fatal("trust not copied to KV")
	}
	cm := e.kube.data(DefaultTrustConfigMap)
	for k, v := range cm {
		if got[k] != v {
			t.Errorf("KV %s differs from the configmap", k)
		}
	}
	e.writeToken(t)
	mustRun(t)
	if e.front.kvWrites != 1 {
		t.Errorf("%d KV writes, want 1 (second run finds it current)", e.front.kvWrites)
	}
}

func TestRunUsageErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  map[string]string
		args []string
	}{
		{"bad configmap name", map[string]string{EnvTrustConfigMap: "../secrets"}, nil},
		{"token env and file", map[string]string{natskeys.EnvPrefixBoot + natskeys.EnvOpenBaoToken: "x"}, nil},
		{"kubernetes auth with token file", map[string]string{natskeys.EnvPrefixBoot + natskeys.EnvOpenBaoAuthMethod: "kubernetes"}, nil},
		{"bad kv path", map[string]string{EnvKVCopy: "true", EnvKVPath: "a/../b"}, nil},
		{"bad fence user", map[string]string{EnvBusFenceUserPub: "not-a-key"}, nil},
		{"bad loader user", map[string]string{EnvBusLoaderUserPub: "not-a-key"}, nil},
		{"loader user is the fence user", map[string]string{EnvBusFenceUserPub: sharedUserPub, EnvBusLoaderUserPub: sharedUserPub}, nil},
		{"no openbao address", map[string]string{natskeys.EnvPrefixBoot + natskeys.EnvOpenBaoAddr: ""}, nil},
		{"extra argument", nil, []string{"extra"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := setup(t)
			e.writeToken(t)
			for k, v := range tc.set {
				t.Setenv(k, v)
			}
			if code, out := runCmd(t, tc.args...); code != 2 {
				t.Errorf("exit %d, want 2; output:\n%s", code, out)
			}
			if e.transit.Count(natskeystest.OpCreateKey) != 0 || e.kube.writeCount() != 0 {
				t.Error("a configuration error still created keys or wrote the configmap")
			}
			if _, err := os.Stat(e.tokenFile); tc.args == nil && !os.IsNotExist(err) {
				t.Errorf("token file still present after a configuration error (stat err %v)", err)
			}
		})
	}
}

func TestRunEmptyTokenFileFails(t *testing.T) {
	e := setup(t)
	if err := os.WriteFile(e.tokenFile, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := runCmd(t); code != 1 || !strings.Contains(out, "empty") {
		t.Errorf("exit %d, want 1; output:\n%s", code, out)
	}
}
