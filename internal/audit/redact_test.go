package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"sort"
	"strings"
	"testing"

	"github.com/m-mizutani/masq"
	"github.com/nats-io/nkeys"
)

// Fixtures: secrets of each kind the string patterns mask.
const (
	testJWT  = "eyJhbGciOiJlZDI1NTE5LW5rZXkiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJVQUJDIiwibmFtZSI6ImFsaWNlIn0.c2lnbmF0dXJlLWJ5dGVzLWhlcmU"
	testAKIA = "AKIAIOSFODNN7EXAMPLE"
)

func testSeed(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := kp.Seed()
	if err != nil {
		t.Fatal(err)
	}
	return string(seed)
}

func testPEM(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// pemBody is the base64 body of a PEM block: what must not survive.
func pemBody(p string) string {
	lines := strings.Split(strings.TrimSpace(p), "\n")
	return strings.Join(lines[1:len(lines)-1], "")
}

// The brief's first check: masq, given a string leaf as a slog attribute,
// replaces each pattern. If it did not, the string leaves would use
// regexp alone.
func TestMasqReplacesEachStringPattern(t *testing.T) {
	seed := testSeed(t)
	pemKey := testPEM(t)
	// pattern is the index in stringPatterns.
	leaves := []struct {
		name, in, secret string
		pattern          int
	}{
		{"pem", "key:\n" + pemKey + "tail", pemBody(pemKey), 0},
		{"jwt", "nats --creds x " + testJWT + " sub", testJWT, 1},
		{"nats seed", "seed is " + seed, seed, 2},
		{"akia", "aws " + testAKIA + " key", testAKIA, 3},
		{"bearer", "curl -H 'Authorization: Bearer abc.def-ghi' host", "abc.def-ghi", 4},
		{"userinfo", "git clone https://bob:hunter2@git.example.com/r", "hunter2", 5},
		{"name=value", "mysql --password=hunter2 db", "hunter2", 6},
		{"name: value", "x-api-key: k3y-v4lue", "k3y-v4lue", 6},
	}
	covered := map[int]bool{}
	for _, l := range leaves {
		covered[l.pattern] = true
	}
	if len(covered) != len(stringPatterns) {
		t.Fatalf("leaves cover %d of %d patterns", len(covered), len(stringPatterns))
	}
	for _, l := range leaves {
		t.Run(l.name, func(t *testing.T) {
			p := stringPatterns[l.pattern]
			mask := masq.New(masq.WithRegex(p.re, masq.RedactString(func(s string) string {
				return p.re.ReplaceAllString(s, p.repl)
			})))
			got, ok := mask(nil, slog.String("v", l.in)).Value.Any().(string)
			if !ok {
				t.Fatalf("masq returned %T", mask(nil, slog.String("v", l.in)).Value.Any())
			}
			if strings.Contains(strings.ReplaceAll(got, "\n", ""), l.secret) || !strings.Contains(got, Redacted) {
				t.Errorf("masq(%q) = %q", l.in, got)
			}
		})
	}
}

func TestRedactStringPatterns(t *testing.T) {
	seed := testSeed(t)
	pemKey := testPEM(t)
	tests := []struct {
		name, in string
		gone     []string
		kept     []string
	}{
		{"jwt in a command", "imas cmd run 'nats pub --jwt " + testJWT + " x'", []string{testJWT, "c2lnbmF0dXJl"}, []string{"imas cmd run 'nats pub --jwt ", " x'"}},
		{"pem block", "before\n" + pemKey + "after", []string{pemBody(pemKey), "BEGIN PRIVATE KEY"}, []string{"before\n", "after"}},
		{"rsa pem block", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----", []string{"MIIEow"}, nil},
		{"unterminated pem", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQ", []string{"MHcCAQ"}, nil},
		{"nats seed", "export NKEY=" + seed, []string{seed}, []string{"export NKEY="}},
		{"akia", "AWS_ACCESS_KEY_ID " + testAKIA, []string{testAKIA}, []string{"AWS_ACCESS_KEY_ID "}},
		{"bearer", "Authorization: Bearer s3cr3t-tok", []string{"s3cr3t-tok"}, []string{"Authorization"}},
		{"bearer lower", "bearer s3cr3t-tok", []string{"s3cr3t-tok"}, nil},
		{"basic auth header", "Authorization: Basic dXNlcjpwYXNz", []string{"dXNlcjpwYXNz"}, []string{"Authorization"}},
		{"userinfo", "postgres://app:hunter2@db:5432/x", []string{"hunter2", "app:"}, []string{"postgres://", "@db:5432/x"}},
		{"password=", "mysql -u root --password=hunter2 -e 'x'", []string{"hunter2"}, []string{"mysql -u root --password="}},
		{"PASSWORD: quoted", `DB_PASSWORD: "hunter 2"`, []string{"hunter 2"}, []string{"DB_PASSWORD"}},
		{"json-ish in string", `{"api_key": "k-123"}`, []string{"k-123"}, []string{"api_key"}},
		{"token query", "https://x/y?token=abc123&z=1", []string{"abc123"}, []string{"&z=1"}},
		{"X-Api-Key header", "curl -H 'X-Api-Key: zz9' u", []string{"zz9"}, []string{"X-Api-Key"}},
		{"secret=", "client_secret=s3", []string{"=s3"}, []string{"client_secret="}},
		{"plain text", "systemctl restart nginx", nil, []string{"systemctl restart nginx"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactString(tt.in)
			for _, g := range tt.gone {
				if strings.Contains(strings.ReplaceAll(got, "\n", ""), g) {
					t.Errorf("RedactString(%q) = %q, still has %q", tt.in, got, g)
				}
			}
			for _, k := range tt.kept {
				if !strings.Contains(got, k) {
					t.Errorf("RedactString(%q) = %q, lost %q", tt.in, got, k)
				}
			}
		})
	}
}

// Each key word, in any case, at depth 3 inside an array, has its value
// replaced; its sibling is kept.
func TestRedactParamsKeyWords(t *testing.T) {
	keys := []string{
		"pass", "password", "passwd", "passphrase", "secret", "token", "apikey", "api_key", "api-key",
		"private", "seed", "credential", "authorization", "bearer", "cookie", "otp", "sdb", "key_material",
		// Substring matches, and mixed case.
		"DB_Password", "X-Api-Key", "ClientSecret", "refresh_token", "PrivateKey", "Set-Cookie", "credentials", "SDB_REF",
	}
	for _, k := range keys {
		for _, name := range []string{k, strings.ToUpper(k), strings.ToLower(k)} {
			t.Run(name, func(t *testing.T) {
				in := map[string]any{"a": map[string]any{"b": []any{map[string]any{name: "v4lue-s3cret", "port": 5432}}}}
				data, _ := json.Marshal(in)
				out := redactParams(data)
				if bytes.Contains(out, []byte("v4lue-s3cret")) {
					t.Fatalf("redactParams(%s) = %s", data, out)
				}
				var got map[string]any
				dec := json.NewDecoder(bytes.NewReader(out))
				dec.UseNumber()
				if err := dec.Decode(&got); err != nil {
					t.Fatalf("output %s: %v", out, err)
				}
				leaf := got["a"].(map[string]any)["b"].([]any)[0].(map[string]any)
				if leaf[name] != Redacted || leaf["port"] != json.Number("5432") {
					t.Errorf("leaf = %v", leaf)
				}
			})
		}
	}
}

// A secret key's value is replaced whatever its type, and ordinary keys
// are kept as they were (numbers exactly).
func TestRedactParamsValues(t *testing.T) {
	in := `{"sprout_id":"web-1","n":12345678901234567890,"f":1.50,"ok":true,"nil":null,` +
		`"token":{"nested":"x"},"seed":["a","b"],"otp":123456,"list":["fine","Bearer zzz"]}`
	out := redactParams(json.RawMessage(in))
	want := `{"f":1.50,"list":["fine","[REDACTED]"],"n":12345678901234567890,"nil":null,"ok":true,"otp":"[REDACTED]","seed":"[REDACTED]","sprout_id":"web-1","token":"[REDACTED]"}`
	if string(out) != want {
		t.Errorf("redactParams =\n%s\nwant\n%s", out, want)
	}
}

func TestRedactParamsUnparseable(t *testing.T) {
	big := []byte(`{"v":"` + strings.Repeat("a", 2<<20) + `"}`)
	for name, in := range map[string][]byte{
		"invalid json":   []byte(`{"password":"hunter2"`),
		"trailing data":  []byte(`{"a":1} {"password":"hunter2"}`),
		"not json":       []byte("password=hunter2"),
		"2 MiB body":     big,
		"just over 1MiB": []byte(`"` + strings.Repeat("b", maxLoggedParams) + `"`),
	} {
		t.Run(name, func(t *testing.T) {
			out := redactParams(in)
			var got map[string]any
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(in)
			if len(got) != 3 || got["redacted"] != "unparseable" || got["bytes"] != float64(len(in)) || got["sha256"] != hex.EncodeToString(sum[:]) {
				t.Errorf("redactParams = %s", out)
			}
		})
	}
	// Exactly 1 MiB is still walked.
	edge := []byte(`"` + strings.Repeat("c", maxLoggedParams-2) + `"`)
	if out := redactParams(edge); !bytes.Equal(out, edge) {
		t.Errorf("1 MiB body not logged as is (%d bytes out)", len(out))
	}
}

// Every free-form method logs shape only: the raw line holds none of the
// original text, and the shape is exactly rule 2's.
func TestFreeFormMethodsLogShapeOnly(t *testing.T) {
	seed := testSeed(t)
	content := map[string]string{
		"cmd.run":             `{"target":[{"SproutID":"web-1"}],"action":{"command":"echo QUIETCOMMAND > /etc/motd"}}`,
		"cook":                `{"target":[{"SproutID":"web-1"}],"action":{"recipe":"QUIETRECIPE","test":true}}`,
		"props.set":           `{"sprout_id":"web-1","name":"QUIETNAME","value":"QUIETVALUE"}`,
		"shell.open":          `{"sprout_id":"web-1","shell":"/bin/QUIETSHELL","cli_eph_pub":"UVVJRVRFUEg="}`,
		"auth.users.add":      `{"pubkey":"UQUIETUSER","role":"admin","username":"QUIETNAME","boxpub":"QUIETBOXPUB"}`,
		"auth.users.resetkey": `{"pubkey":"UQUIETUSER","boxpub":"QUIETBOXPUB"}`,
		"auth.rotatekey":      `{"box_pub":"QUIETBOXPUB","seed":"` + seed + `"}`,
	}
	if len(content) != len(freeFormMethods) {
		t.Fatalf("%d fixtures for %d free-form methods", len(content), len(freeFormMethods))
	}
	for method, params := range content {
		t.Run(method, func(t *testing.T) {
			if !IsFreeForm(method) {
				t.Fatalf("%s is not free-form", method)
			}
			var buf bytes.Buffer
			if err := NewLogger(&buf).Log(Entry{Pubkey: "UADMIN", Action: method, Targets: []string{"web-1"}, Parameters: json.RawMessage(params), Success: true}); err != nil {
				t.Fatal(err)
			}
			raw := buf.Bytes()
			for _, w := range []string{"QUIET", "UVVJRVRFUEg", seed} {
				if bytes.Contains(raw, []byte(w)) {
					t.Errorf("line holds %q: %s", w, raw)
				}
			}
			var line struct {
				Targets []string        `json:"targets"`
				Params  json.RawMessage `json:"params"`
			}
			if err := json.Unmarshal(raw, &line); err != nil {
				t.Fatal(err)
			}
			var m map[string]json.RawMessage
			_ = json.Unmarshal([]byte(params), &m)
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			sum := sha256.Sum256([]byte(params))
			want, _ := json.Marshal(map[string]any{"redacted": "free-form", "bytes": len(params), "sha256": hex.EncodeToString(sum[:]), "keys": keys})
			if !jsonEqual(t, line.Params, want) {
				t.Errorf("params = %s, want %s", line.Params, want)
			}
			if len(line.Targets) != 1 || line.Targets[0] != "web-1" {
				t.Errorf("targets = %v", line.Targets)
			}
		})
	}
}

// A free-form method's params that are not an object, or not JSON, still
// log shape only, with no keys.
func TestFreeFormNotObject(t *testing.T) {
	for _, in := range []string{`["QUIET"]`, `{"QUIET"`, `"QUIET"`} {
		out := freeFormShape(json.RawMessage(in))
		var got map[string]any
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out, []byte("QUIET")) || got["redacted"] != "free-form" || len(got["keys"].([]any)) != 0 {
			t.Errorf("freeFormShape(%s) = %s", in, out)
		}
	}
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatalf("%s: %v", a, err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}

// Entry.Error is masked; the other fields are not touched.
func TestLogRedactsError(t *testing.T) {
	seed := testSeed(t)
	var buf bytes.Buffer
	e := Entry{Username: "alice", Pubkey: "UALICE", RoleName: "dev", Action: "pki.accept", Targets: []string{"web-1"},
		Error: "dial postgres://app:hunter2@db failed; token=" + testJWT + " seed " + seed}
	if err := NewLogger(&buf).Log(e); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"hunter2", testJWT, seed} {
		if bytes.Contains(buf.Bytes(), []byte(s)) {
			t.Errorf("line holds %q: %s", s, buf.Bytes())
		}
	}
	var got Entry
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Username != "alice" || got.Pubkey != "UALICE" || got.RoleName != "dev" || got.Action != "pki.accept" ||
		len(got.Targets) != 1 || !strings.HasPrefix(got.Error, "dial postgres://[REDACTED]@db failed") {
		t.Errorf("entry = %+v", got)
	}
	// The caller's entry is a copy: Log changes nothing the caller holds.
	if !strings.Contains(e.Error, "hunter2") {
		t.Error("Log changed the caller's entry")
	}
}

// A read-only method's entry is written as before.
func TestLogReadOnlyUnchanged(t *testing.T) {
	var buf bytes.Buffer
	if err := NewLogger(&buf).Log(Entry{Pubkey: "UADMIN", RoleName: "admin", Action: "sprouts.list", Success: true}); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "ts")
	want := map[string]any{"kind": "audit", "pubkey": "UADMIN", "role": "admin", "action": "sprouts.list", "success": true}
	if len(m) != len(want) {
		t.Fatalf("line = %v", m)
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %v, want %v", k, m[k], v)
		}
	}
}

// An ordinary write's params keep everything but the secrets.
func TestLogOrdinaryWriteMasked(t *testing.T) {
	seed := testSeed(t)
	params := `{"sprout_id":"web-1","password":"hunter2","X-Api-Key":"k-123","note":"use ` + seed + ` and ` + testJWT + `"}`
	var buf bytes.Buffer
	if err := NewLogger(&buf).Log(Entry{Action: "pki.accept", Parameters: json.RawMessage(params)}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"hunter2", "k-123", seed, testJWT} {
		if bytes.Contains(buf.Bytes(), []byte(s)) {
			t.Errorf("line holds %q: %s", s, buf.Bytes())
		}
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"sprout_id":"web-1"`)) {
		t.Errorf("line lost sprout_id: %s", buf.Bytes())
	}
}
