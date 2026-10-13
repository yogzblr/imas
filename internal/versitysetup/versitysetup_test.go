package versitysetup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	rootAccess = "vgw-root"
	rootSecret = "root-secret-key-0123456789"
)

// writeCred writes one credential directory.
func writeCred(t *testing.T, dir, access, secret string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, AccessKeyIDFile), []byte(access), 0o600); err != nil {
		t.Fatal(err)
	}
	if secret != "" {
		if err := os.WriteFile(filepath.Join(dir, SecretAccessKeyFile), []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// fixture is a root credential and the chart's four users, laid out as
// the chart's projected volumes are.
type fixture struct {
	root, users string
}

var chartUsers = map[string][2]string{
	"farmer":          {"farmer-key", "farmer-secret-0001"},
	"accounts-writer": {"acc-writer-key", "acc-writer-secret-01"},
	"accounts-reader": {"acc-reader-key", "acc-reader-secret-01"},
	"saasapi-recipes": {"saasapi-key", "saasapi-secret-0001"},
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	d := t.TempDir()
	f := fixture{root: filepath.Join(d, "root"), users: filepath.Join(d, "users")}
	writeCred(t, f.root, rootAccess, rootSecret)
	for name, c := range chartUsers {
		writeCred(t, filepath.Join(f.users, name), c[0], c[1])
	}
	// What a projected Secret volume also holds.
	if err := os.Symlink(".", filepath.Join(f.users, "..data")); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestWriteIAM(t *testing.T) {
	f := newFixture(t)
	out := t.TempDir()
	var stderr bytes.Buffer
	if code := RunIAM([]string{"-users-dir", f.users, "-root-dir", f.root, "-out", out}, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	b, err := os.ReadFile(filepath.Join(out, IAMFile))
	if err != nil {
		t.Fatal(err)
	}
	var conf struct {
		AccessAccounts map[string]map[string]any `json:"accessAccounts"`
	}
	if err := json.Unmarshal(b, &conf); err != nil {
		t.Fatal(err)
	}
	if len(conf.AccessAccounts) != len(chartUsers) {
		t.Fatalf("%d accounts, want %d: %s", len(conf.AccessAccounts), len(chartUsers), b)
	}
	for _, c := range chartUsers {
		a := conf.AccessAccounts[c[0]]
		if a["access"] != c[0] || a["secret"] != c[1] || a["role"] != "user" {
			t.Errorf("account %s = %v", c[0], a)
		}
	}
	if _, ok := conf.AccessAccounts[rootAccess]; ok {
		t.Error("the root is in the IAM file")
	}
	st, err := os.Stat(filepath.Join(out, IAMFile))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o400 {
		t.Errorf("mode %v, want 0400", st.Mode().Perm())
	}
	if !strings.Contains(stderr.String(), "wrote 4 users") {
		t.Errorf("output %q", stderr.String())
	}
	// No secret in the output.
	for _, c := range chartUsers {
		if strings.Contains(stderr.String(), c[1]) {
			t.Error("a secret key was logged")
		}
	}
	// A second run replaces the file (a pod restart writes a fresh one).
	if code := RunIAM([]string{"-users-dir", f.users, "-root-dir", f.root, "-out", out}, &stderr); code != 0 {
		t.Fatalf("second run exit %d: %s", code, stderr.String())
	}
}

func TestWriteIAMRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(t *testing.T, f fixture)
		want   string
	}{
		"root access key reused": {func(t *testing.T, f fixture) {
			writeCred(t, filepath.Join(f.users, "farmer"), rootAccess, "farmer-secret-0001")
		}, "root access key ID"},
		"two users share a key": {func(t *testing.T, f fixture) {
			writeCred(t, filepath.Join(f.users, "saasapi-recipes"), "farmer-key", "saasapi-secret-0001")
		}, "same access key ID"},
		"trailing newline": {func(t *testing.T, f fixture) {
			writeCred(t, filepath.Join(f.users, "farmer"), "farmer-key", "farmer-secret-0001\n")
		}, "no whitespace"},
		"access key with a slash": {func(t *testing.T, f fixture) {
			writeCred(t, filepath.Join(f.users, "farmer"), "farmer/key", "farmer-secret-0001")
		}, "access key ID must be"},
		"short secret": {func(t *testing.T, f fixture) {
			writeCred(t, filepath.Join(f.users, "farmer"), "farmer-key", "short")
		}, "8 to 128"},
		"missing secret": {func(t *testing.T, f fixture) {
			if err := os.Remove(filepath.Join(f.users, "farmer", SecretAccessKeyFile)); err != nil {
				t.Fatal(err)
			}
		}, "farmer credential"},
		"bad user name": {func(t *testing.T, f fixture) {
			writeCred(t, filepath.Join(f.users, "Bad_Name"), "other-key", "other-secret-0001")
		}, "not a user name"},
		"no users": {func(t *testing.T, f fixture) {
			for name := range chartUsers {
				if err := os.RemoveAll(filepath.Join(f.users, name)); err != nil {
					t.Fatal(err)
				}
			}
		}, "holds no user"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			tc.mutate(t, f)
			out := t.TempDir()
			var stderr bytes.Buffer
			if code := RunIAM([]string{"-users-dir", f.users, "-root-dir", f.root, "-out", out}, &stderr); code != 2 {
				t.Fatalf("exit %d, want 2: %s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("output %q, want %q", stderr.String(), tc.want)
			}
			if _, err := os.Stat(filepath.Join(out, IAMFile)); !os.IsNotExist(err) {
				t.Error("an IAM file was written")
			}
		})
	}
	var stderr bytes.Buffer
	if code := RunIAM([]string{"-users-dir", "x"}, &stderr); code != 2 {
		t.Errorf("missing flags: exit %d", code)
	}
}

// fakeGateway is just enough of the S3 API for EnsureBuckets: bucket
// create, and put and get of a bucket policy, each signed with the root
// access key.
type fakeGateway struct {
	mu       sync.Mutex
	buckets  map[string]string // name -> policy
	foreign  map[string]bool   // buckets someone else owns
	fail     []int             // status codes for the next requests
	failCode []string
	// malformed answers MalformedPolicy to this many policy writes.
	malformed int
	// mangle, if set, changes what a policy read returns.
	mangle   bool
	requests []string
}

var credRe = regexp.MustCompile(`Credential=([^/]+)/`)

func (g *fakeGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	errXML := func(status int, code string) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(status)
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
	}
	g.requests = append(g.requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
	if len(g.fail) > 0 {
		status, code := g.fail[0], g.failCode[0]
		g.fail, g.failCode = g.fail[1:], g.failCode[1:]
		errXML(status, code)
		return
	}
	if m := credRe.FindStringSubmatch(r.Header.Get("Authorization")); m == nil || m[1] != rootAccess {
		errXML(http.StatusForbidden, "InvalidAccessKeyId")
		return
	}
	name := strings.Trim(r.URL.Path, "/")
	_, policyReq := r.URL.Query()["policy"]
	switch {
	case r.Method == http.MethodPut && !policyReq:
		if g.foreign[name] {
			errXML(http.StatusConflict, "BucketAlreadyExists")
			return
		}
		if _, ok := g.buckets[name]; ok {
			errXML(http.StatusConflict, "BucketAlreadyOwnedByYou")
			return
		}
		g.buckets[name] = ""
	case r.Method == http.MethodPut && policyReq:
		if _, ok := g.buckets[name]; !ok {
			errXML(http.StatusNotFound, "NoSuchBucket")
			return
		}
		if g.malformed > 0 {
			g.malformed--
			errXML(http.StatusBadRequest, "MalformedPolicy")
			return
		}
		b, _ := io.ReadAll(r.Body)
		g.buckets[name] = string(b)
		w.WriteHeader(http.StatusNoContent)
		return
	case r.Method == http.MethodGet && policyReq:
		p, ok := g.buckets[name]
		if !ok || p == "" {
			errXML(http.StatusNotFound, "NoSuchBucketPolicy")
			return
		}
		if g.mangle {
			p = strings.Replace(p, "s3:GetObject", "s3:DeleteObject", 1)
		}
		_, _ = io.WriteString(w, p)
		return
	default:
		errXML(http.StatusNotImplemented, "NotImplemented")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func startGateway(t *testing.T) (*fakeGateway, string) {
	t.Helper()
	g := &fakeGateway{buckets: map[string]string{}, foreign: map[string]bool{}}
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	return g, strings.TrimPrefix(srv.URL, "http://")
}

const testPlan = `{"buckets": [
 {"name": "imas-recipes", "statements": [
  {"sid": "FarmerBucket", "user": "farmer", "actions": ["s3:GetBucketLocation", "s3:ListBucket"], "resources": ["arn:aws:s3:::imas-recipes"]},
  {"sid": "FarmerObjects", "user": "farmer", "actions": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], "resources": ["arn:aws:s3:::imas-recipes/*"]},
  {"sid": "SaasapiList", "user": "saasapi-recipes", "actions": ["s3:ListBucket"], "resources": ["arn:aws:s3:::imas-recipes"],
   "condition": {"StringLike": {"s3:prefix": ["tenants/*/recipes/*"]}}}
 ]},
 {"name": "imas-accounts", "statements": [
  {"sid": "WriterBucket", "user": "accounts-writer", "actions": ["s3:ListBucket"], "resources": ["arn:aws:s3:::imas-accounts"]},
  {"sid": "ReaderObjects", "user": "accounts-reader", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::imas-accounts/*"]}
 ]}
]}`

func writePlan(t *testing.T, plan string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "buckets.json")
	if err := os.WriteFile(p, []byte(plan), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func bucketsCfg(f fixture, endpoint, plan string) BucketsConfig {
	return BucketsConfig{Endpoint: endpoint, Region: "us-east-1", RootDir: f.root, UsersDir: f.users, PlanFile: plan, RetryWait: time.Millisecond}
}

func TestEnsureBuckets(t *testing.T) {
	f := newFixture(t)
	// The Job mounts only the users' access key IDs.
	for name := range chartUsers {
		if err := os.Remove(filepath.Join(f.users, name, SecretAccessKeyFile)); err != nil {
			t.Fatal(err)
		}
	}
	g, ep := startGateway(t)
	plan := writePlan(t, testPlan)
	var out bytes.Buffer
	if err := EnsureBuckets(context.Background(), bucketsCfg(f, ep, plan), &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(g.buckets) != 2 {
		t.Fatalf("buckets %v", g.buckets)
	}
	var p struct {
		Statement []struct {
			Sid       string
			Effect    string
			Principal map[string][]string
			Action    []string
			Resource  []string
			Condition map[string]map[string][]string
		}
	}
	if err := json.Unmarshal([]byte(g.buckets["imas-recipes"]), &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Statement) != 3 {
		t.Fatalf("statements %+v", p.Statement)
	}
	for _, s := range p.Statement {
		if s.Effect != "Allow" {
			t.Errorf("%s: effect %s", s.Sid, s.Effect)
		}
	}
	if got := p.Statement[0].Principal["AWS"]; len(got) != 1 || got[0] != "farmer-key" {
		t.Errorf("farmer principal %v", got)
	}
	if got := p.Statement[2].Principal["AWS"]; len(got) != 1 || got[0] != "saasapi-key" {
		t.Errorf("saasapi principal %v", got)
	}
	if got := p.Statement[2].Condition["StringLike"]["s3:prefix"]; len(got) != 1 || got[0] != "tenants/*/recipes/*" {
		t.Errorf("condition %v", p.Statement[2].Condition)
	}
	if !strings.Contains(g.buckets["imas-accounts"], `"acc-reader-key"`) || strings.Contains(g.buckets["imas-accounts"], "farmer-key") {
		t.Errorf("accounts policy %s", g.buckets["imas-accounts"])
	}

	// Idempotent: the root already owns both; the policies are written
	// again (so a grant removed from the plan goes).
	g.buckets["imas-accounts"] = `{"stale": true}`
	out.Reset()
	if err := EnsureBuckets(context.Background(), bucketsCfg(f, ep, plan), &out); err != nil {
		t.Fatalf("second run: %v\n%s", err, out.String())
	}
	if strings.Contains(g.buckets["imas-accounts"], "stale") {
		t.Error("the second run kept the old policy")
	}
}

func TestEnsureBucketsRetriesAndRefusals(t *testing.T) {
	f := newFixture(t)
	plan := writePlan(t, testPlan)

	t.Run("gateway starting", func(t *testing.T) {
		g, ep := startGateway(t)
		g.fail = []int{503, 500}
		g.failCode = []string{"ServiceUnavailable", "InternalError"}
		g.malformed = 2
		var out bytes.Buffer
		if err := EnsureBuckets(context.Background(), bucketsCfg(f, ep, plan), &out); err != nil {
			t.Fatalf("%v\n%s", err, out.String())
		}
		if !strings.Contains(out.String(), "retrying") {
			t.Errorf("no retry logged: %s", out.String())
		}
	})
	t.Run("unreachable until the deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		err := EnsureBuckets(ctx, bucketsCfg(f, "127.0.0.1:1", plan), io.Discard)
		if err == nil || !strings.Contains(err.Error(), "gave up") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("bucket owned by someone else", func(t *testing.T) {
		g, ep := startGateway(t)
		g.foreign["imas-recipes"] = true
		err := EnsureBuckets(context.Background(), bucketsCfg(f, ep, plan), io.Discard)
		if err == nil || !strings.Contains(err.Error(), "BucketAlreadyExists") && !strings.Contains(err.Error(), "already") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("access denied is final", func(t *testing.T) {
		g, ep := startGateway(t)
		g.fail = []int{403}
		g.failCode = []string{"AccessDenied"}
		err := EnsureBuckets(context.Background(), bucketsCfg(f, ep, plan), io.Discard)
		if err == nil || len(g.requests) != 1 {
			t.Fatalf("err %v after %d requests", err, len(g.requests))
		}
	})
	t.Run("policy read back differs", func(t *testing.T) {
		g, ep := startGateway(t)
		g.mangle = true
		err := EnsureBuckets(context.Background(), bucketsCfg(f, ep, plan), io.Discard)
		if err == nil || !strings.Contains(err.Error(), "different policy") {
			t.Fatalf("err %v", err)
		}
	})
}

func TestBucketsPlanRefused(t *testing.T) {
	f := newFixture(t)
	for name, tc := range map[string]struct{ plan, want string }{
		"resource in another bucket": {`{"buckets":[{"name":"imas-accounts","statements":[{"sid":"A","user":"farmer","actions":["s3:GetObject"],"resources":["arn:aws:s3:::imas-recipes/*"]}]}]}`, "outside the bucket"},
		"prefix of another bucket":   {`{"buckets":[{"name":"imas-a","statements":[{"sid":"A","user":"farmer","actions":["s3:GetObject"],"resources":["arn:aws:s3:::imas-ab/*"]}]}]}`, "outside the bucket"},
		"wildcard action":            {`{"buckets":[{"name":"imas-accounts","statements":[{"sid":"A","user":"farmer","actions":["s3:*"],"resources":["arn:aws:s3:::imas-accounts"]}]}]}`, "plain s3: action"},
		"unknown user":               {`{"buckets":[{"name":"imas-accounts","statements":[{"sid":"A","user":"nobody","actions":["s3:GetObject"],"resources":["arn:aws:s3:::imas-accounts/*"]}]}]}`, "no credential"},
		"container name":             {`{"buckets":[{"name":"imas--x","statements":[{"sid":"A","user":"farmer","actions":["s3:GetObject"],"resources":["arn:aws:s3:::imas--x/*"]}]}]}`, "container name"},
		"upper case":                 {`{"buckets":[{"name":"Imas","statements":[{"sid":"A","user":"farmer","actions":["s3:GetObject"],"resources":["arn:aws:s3:::Imas/*"]}]}]}`, "container name"},
		"listed twice":               {`{"buckets":[{"name":"imas-a","statements":[{"sid":"A","user":"farmer","actions":["s3:GetObject"],"resources":["arn:aws:s3:::imas-a/*"]}]},{"name":"imas-a","statements":[{"sid":"A","user":"farmer","actions":["s3:GetObject"],"resources":["arn:aws:s3:::imas-a/*"]}]}]}`, "twice"},
		"no statement":               {`{"buckets":[{"name":"imas-a","statements":[]}]}`, "no statement"},
		"no bucket":                  {`{"buckets":[]}`, "no bucket"},
		"repeated sid":               {`{"buckets":[{"name":"imas-a","statements":[{"sid":"A","user":"farmer","actions":["s3:GetObject"],"resources":["arn:aws:s3:::imas-a/*"]},{"sid":"A","user":"farmer","actions":["s3:PutObject"],"resources":["arn:aws:s3:::imas-a/*"]}]}]}`, "repeated"},
		"unknown field":              {`{"buckets":[{"name":"imas-a","effect":"Deny","statements":[]}]}`, "unknown field"},
		"bad condition":              {`{"buckets":[{"name":"imas-a","statements":[{"sid":"A","user":"farmer","actions":["s3:ListBucket"],"resources":["arn:aws:s3:::imas-a"],"condition":["x"]}]}]}`, "condition"},
	} {
		t.Run(name, func(t *testing.T) {
			_, ep := startGateway(t)
			var stderr bytes.Buffer
			code := RunBuckets([]string{"-endpoint", ep, "-root-dir", f.root, "-users-dir", f.users, "-plan", writePlan(t, tc.plan)}, &stderr)
			if code != 2 || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("exit %d, output %q, want 2 and %q", code, stderr.String(), tc.want)
			}
		})
	}
	var stderr bytes.Buffer
	if code := RunBuckets([]string{"-endpoint", "x:1"}, &stderr); code != 2 {
		t.Errorf("missing flags: exit %d", code)
	}
}

func TestRunBucketsExitCodes(t *testing.T) {
	f := newFixture(t)
	g, ep := startGateway(t)
	plan := writePlan(t, testPlan)
	var stderr bytes.Buffer
	if code := RunBuckets([]string{"-endpoint", ep, "-root-dir", f.root, "-users-dir", f.users, "-plan", plan}, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "bucket imas-accounts ready") || strings.Contains(stderr.String(), rootSecret) {
		t.Errorf("output %q", stderr.String())
	}
	g.foreign["imas-jobs"] = true
	stderr.Reset()
	other := writePlan(t, `{"buckets":[{"name":"imas-jobs","statements":[{"sid":"A","user":"farmer","actions":["s3:GetObject"],"resources":["arn:aws:s3:::imas-jobs/*"]}]}]}`)
	if code := RunBuckets([]string{"-endpoint", ep, "-root-dir", f.root, "-users-dir", f.users, "-plan", other}, &stderr); code != 1 {
		t.Fatalf("foreign bucket: exit %d: %s", code, stderr.String())
	}
}
