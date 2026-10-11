package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/accountloader"
)

func required() map[string]string {
	return map[string]string{
		envS3Endpoint:      "s3.example:443",
		envS3Bucket:        "imas-accounts",
		envS3KeyIDFile:     "/s3/access-key-id",
		envS3SecretFile:    "/s3/secret-access-key",
		envNATSServerName:  "imas-bus.imas.svc.cluster.local",
		envCAFile:          "/tls/ca.crt",
		envSysUserJWTFile:  "/sys/user.jwt",
		envSysUserSeedFile: "/sys/user.nk",
	}
}

func getenv(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestParseEnvDefaults(t *testing.T) {
	s, err := parseEnv(getenv(required()))
	if err != nil {
		t.Fatal(err)
	}
	want := settings{
		S3Endpoint: "s3.example:443", S3UseSSL: true, S3Bucket: "imas-accounts",
		S3KeyIDFile: "/s3/access-key-id", S3SecretFile: "/s3/secret-access-key",
		NATSURL: "tls://127.0.0.1:4222", NATSServerName: "imas-bus.imas.svc.cluster.local",
		CAFile: "/tls/ca.crt", SysUserJWTFile: "/sys/user.jwt", SysUserSeedFile: "/sys/user.nk",
		TrustDir: "/var/run/imas/nats-trust", EventSubject: "imas.bus.accounts.changed",
		Reconcile: 30 * time.Second, FullResync: 5 * time.Minute,
		PushConcurrency: 8, PushRate: 200, HealthPort: "8081",
	}
	if s != want {
		t.Errorf("settings =\n%+v\nwant\n%+v", s, want)
	}
}

func TestParseEnvOverrides(t *testing.T) {
	m := required()
	m[envS3UseSSL] = "false"
	m[envNATSURL] = "tls://127.0.0.1:14222"
	m[envEventSubject] = "x.y"
	m[envReconcile] = "10s"
	m[envFullResync] = "1m"
	m[envPushConcurrency] = "2"
	m[envPushRate] = "50/s"
	m[envHealthPort] = "9000"
	m[envTrustDir] = "/trust"
	s, err := parseEnv(getenv(m))
	if err != nil {
		t.Fatal(err)
	}
	if s.S3UseSSL || s.NATSURL != "tls://127.0.0.1:14222" || s.EventSubject != "x.y" || s.Reconcile != 10*time.Second ||
		s.FullResync != time.Minute || s.PushConcurrency != 2 || s.PushRate != 50 || s.HealthPort != "9000" || s.TrustDir != "/trust" {
		t.Errorf("settings = %+v", s)
	}
	m[envPushRate] = "25"
	if s, _ := parseEnv(getenv(m)); s.PushRate != 25 {
		t.Errorf("rate without /s = %v", s.PushRate)
	}
}

func TestParseEnvErrors(t *testing.T) {
	_, err := parseEnv(getenv(map[string]string{}))
	if err == nil {
		t.Fatal("empty environment accepted")
	}
	for _, name := range []string{envS3Endpoint, envS3Bucket, envS3KeyIDFile, envS3SecretFile, envNATSServerName, envCAFile, envSysUserJWTFile, envSysUserSeedFile} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error does not name missing %s: %v", name, err)
		}
	}
	for name, bad := range map[string]string{
		envS3Endpoint:      "https://s3.example",
		envS3UseSSL:        "maybe",
		envReconcile:       "-1s",
		envFullResync:      "soon",
		envPushConcurrency: "0",
		envPushRate:        "fast",
		envHealthPort:      "70000",
	} {
		m := required()
		m[name] = bad
		if _, err := parseEnv(getenv(m)); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s=%q: err = %v", name, bad, err)
		}
	}
}

func writeTrust(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for k, v := range files {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func pub(t *testing.T, create func() (nkeys.KeyPair, error)) string {
	t.Helper()
	kp, err := create()
	if err != nil {
		t.Fatal(err)
	}
	p, _ := kp.PublicKey()
	return p
}

func TestLoadTrust(t *testing.T) {
	op, sk, sys := pub(t, nkeys.CreateOperator), pub(t, nkeys.CreateOperator), pub(t, nkeys.CreateAccount)
	good := map[string]string{trustOperatorPub: op, trustOperatorSigningPub: sk, trustSysAccountPub: sys}
	tr, err := loadTrust(writeTrust(t, good))
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Operators) != 2 || tr.Operators[0] != op || tr.Operators[1] != sk || tr.SysAccount != sys {
		t.Errorf("trust = %+v", tr)
	}
	for name, mut := range map[string]func(map[string]string){
		"missing signing key":     func(m map[string]string) { delete(m, trustOperatorSigningPub) },
		"account as operator":     func(m map[string]string) { m[trustOperatorPub] = sys },
		"operator as SYS account": func(m map[string]string) { m[trustSysAccountPub] = op },
		"missing SYS account":     func(m map[string]string) { delete(m, trustSysAccountPub) },
	} {
		m := map[string]string{}
		for k, v := range good {
			m[k] = v
		}
		mut(m)
		if _, err := loadTrust(writeTrust(t, m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestHealthMux(t *testing.T) {
	ready := false
	mux := healthMux(func() bool { return ready }, func() accountloader.Status {
		return accountloader.Status{Ready: ready, State: "x", Applied: 3, Invalid: []accountloader.InvalidObject{}}
	})
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	if c := get("/healthz").Code; c != http.StatusOK {
		t.Errorf("/healthz = %d", c)
	}
	if c := get("/readyz").Code; c != http.StatusServiceUnavailable {
		t.Errorf("/readyz before ready = %d", c)
	}
	ready = true
	if c := get("/readyz").Code; c != http.StatusOK {
		t.Errorf("/readyz when ready = %d", c)
	}
	w := get("/status")
	var st accountloader.Status
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil || !st.Ready || st.Applied != 3 {
		t.Errorf("/status = %s (%v)", w.Body.String(), err)
	}
}

func TestTLSConfig(t *testing.T) {
	if _, err := tlsConfig(filepath.Join(t.TempDir(), "none"), "x"); err == nil {
		t.Error("missing CA accepted")
	}
	bad := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(bad, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsConfig(bad, "x"); err == nil {
		t.Error("CA file without certificates accepted")
	}
}

func TestOpenStoreReadsCredentialFiles(t *testing.T) {
	dir := t.TempDir()
	id, secret := filepath.Join(dir, "id"), filepath.Join(dir, "secret")
	s := settings{S3Endpoint: "127.0.0.1:9", S3Bucket: "imas-accounts", S3KeyIDFile: id, S3SecretFile: secret}
	if _, err := openStore(s)(); err == nil {
		t.Error("opened without credential files")
	}
	for _, f := range []string{id, secret} {
		if err := os.WriteFile(f, []byte("v\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := openStore(s)(); err != nil {
		t.Errorf("open: %v", err)
	}
}
