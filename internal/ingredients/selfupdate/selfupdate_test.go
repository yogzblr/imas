package selfupdate

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/ingredients"
)

const (
	testJWT       = "gateway.jwt.token"
	testRunning   = "v2.4.0"
	testTarget    = "v2.4.1"
	testFileDeb   = "imas-sprout_2.4.1_linux_amd64.deb"
	testFileRPM   = "imas-sprout_2.4.1_linux_amd64.rpm"
	testFileMSI   = "imas-sprout-2.4.1-windows-amd64.msi"
	testRepoToken = "repo-secret"
)

var pkgBytes = []byte("!<arch>\ndebian-binary   imas-sprout 2.4.1\n")

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// call is one recorded installer or systemctl invocation.
type call struct {
	name string
	args []string
	env  []string
}

// fixture stands up a farmer (its own CA, pinned as SproutRootCA) serving
// manifests, a separate HTTPS repository, a shipped keyring, and fake
// installers, and records what reaches each of them.
type fixture struct {
	t *testing.T

	priv     ed25519.PrivateKey
	keyID    int
	manifest fleetsign.Manifest // signed in serveManifest unless rawManifest is set
	// rawManifest, if set, is served verbatim instead.
	rawManifest  []byte
	farmerStatus int // 0: 200 with the manifest

	farmer      *httptest.Server
	farmerCAPEM []byte
	repo        *httptest.Server
	repoBody    []byte

	mu         sync.Mutex
	farmerReqs []*http.Request
	repoReqs   []*http.Request
	calls      []call
	detached   []call
	deferred   []func()
	// failInstall makes the installer exit with this error.
	failInstall error
	// rejectJWT makes farmer answer 401 to this token.
	rejectJWT string
	refreshes int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, keyID: 1, repoBody: pkgBytes}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f.priv = priv
	f.manifest = fleetsign.Manifest{
		Version: testTarget, OS: "linux", Arch: "amd64", FileName: testFileDeb,
		ChecksumSHA256: sha(pkgBytes), MinSproutVersion: "v2.0.0",
	}

	dir := t.TempDir()

	// Farmer, with a certificate from its own CA: only SproutRootCA
	// trusts it.
	f.farmer, f.farmerCAPEM = newCAServer(t, http.HandlerFunc(f.serveManifest))

	// The repository: httptest's built-in certificate, trusted only via
	// repoRootCAs (the tests' stand-in for the OS trust store).
	f.repo = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.record(&f.repoReqs, r)
		if r.URL.Path != "/repo/imasdeb/"+testFileDeb && r.URL.Path != "/repo/imasdeb/"+testFileRPM &&
			r.URL.Path != "/repo/imasdeb/"+testFileMSI {
			http.NotFound(w, r)
			return
		}
		w.Write(f.repoBody)
	}))
	t.Cleanup(f.repo.Close)
	repoPool := x509.NewCertPool()
	repoPool.AddCert(f.repo.Certificate())

	rootCA := filepath.Join(dir, "tls-rootca.pem")
	writeFile(t, rootCA, f.farmerCAPEM, 0o644)
	keyring := filepath.Join(dir, "fleet-signing-keys.json")
	writeFile(t, keyring, keyringJSON(1, pub), 0o644)

	saveConfig(t)
	config.SproutRootCA = rootCA
	config.FarmerURL = f.farmer.URL
	config.CacheDir = filepath.Join(dir, "cache")
	config.SproutFleetSigningKeyring = keyring
	config.SproutUpdateRepoURL = f.repo.URL + "/repo/imasdeb/"
	config.SproutUpdateRepoToken = ""

	// Platform: Debian, with fake tools and a running systemd.
	tools := filepath.Join(dir, "bin")
	for _, name := range []string{"dpkg", "rpm", "zypper", "systemctl"} {
		writeFile(t, filepath.Join(tools, name), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	}
	osRelease := filepath.Join(dir, "os-release")
	writeFile(t, osRelease, []byte("ID=debian\nVERSION_ID=\"12\"\n"), 0o644)
	sysd := filepath.Join(dir, "run-systemd-system")
	if err := os.Mkdir(sysd, 0o755); err != nil {
		t.Fatal(err)
	}
	winRoot := filepath.Join(dir, "Windows")
	writeFile(t, filepath.Join(winRoot, "System32", "msiexec.exe"), []byte("MZ"), 0o755)

	setSeam(t, &goos, "linux")
	setSeam(t, &goarch, "amd64")
	setSeam(t, &osReleasePath, osRelease)
	setSeam(t, &toolDirs, []string{tools})
	setSeam(t, &systemdRunDir, sysd)
	setSeam(t, &systemRoot, func() string { return winRoot })
	setSeam(t, &repoRootCAs, repoPool)
	setSeam(t, &runningVersion, func() (string, error) { return testRunning, nil })
	setSeam(t, &gatewayJWT, func(context.Context) (string, error) { return testJWT, nil })
	setSeam(t, &refreshGatewayJWT, func(context.Context) (string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.refreshes++
		return testJWT + ".refreshed", nil
	})
	setSeam(t, &runCommand, func(_ context.Context, name string, args, env []string) ([]byte, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, call{name, args, env})
		if filepath.Base(name) != "systemctl" && f.failInstall != nil {
			return []byte("dpkg: error processing archive"), f.failInstall
		}
		return []byte("Setting up imas-sprout (2.4.1) ..."), nil
	})
	setSeam(t, &startDetached, func(name string, args []string) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.detached = append(f.detached, call{name: name, args: args})
		return nil
	})
	setSeam(t, &afterReport, func(fn func()) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.deferred = append(f.deferred, fn)
	})
	installed.Store(false)
	t.Cleanup(func() { installed.Store(false) })
	return f
}

func (f *fixture) record(dst *[]*http.Request, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	*dst = append(*dst, r.Clone(context.Background()))
}

func (f *fixture) serveManifest(w http.ResponseWriter, r *http.Request) {
	f.record(&f.farmerReqs, r)
	if r.URL.Path != manifestPath {
		http.NotFound(w, r)
		return
	}
	if f.rejectJWT != "" && r.Header.Get("Authorization") == "Bearer "+f.rejectJWT {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if f.farmerStatus != 0 {
		w.WriteHeader(f.farmerStatus)
		return
	}
	body := f.rawManifest
	if body == nil {
		body, _ = json.Marshal(f.signed(f.manifest))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// signed returns m with a signature by f's key, unless m already has one.
func (f *fixture) signed(m fleetsign.Manifest) fleetsign.Manifest {
	if m.Signature != "" {
		return m
	}
	msg, err := m.Message()
	if err != nil {
		f.t.Fatalf("manifest message: %v", err)
	}
	m.Signature = fleetsign.EncodeSignature(f.keyID, ed25519.Sign(f.priv, msg))
	return m
}

// runDeferred runs what the step left to run after its result is
// reported (the restart, or msiexec).
func (f *fixture) runDeferred() {
	f.mu.Lock()
	fns := f.deferred
	f.deferred = nil
	f.mu.Unlock()
	for _, fn := range fns {
		fn()
	}
}

func (f *fixture) counts() (farmer, repo, installs int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if filepath.Base(c.name) != "systemctl" {
			installs++
		}
	}
	return len(f.farmerReqs), len(f.repoReqs), installs + len(f.detached)
}

func step(t *testing.T, props map[string]interface{}) cook.RecipeCooker {
	t.Helper()
	rc, err := SelfUpdate{}.Parse("selfupdate-"+testTarget, fleetsign.SelfUpdateMethod, props)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return rc
}

func target(v string) map[string]interface{} {
	return map[string]interface{}{fleetsign.PropVersion: v}
}

func TestApply_Deb_DownloadsVerifiesAndInstalls(t *testing.T) {
	f := newFixture(t)
	res, err := step(t, target(testTarget)).Apply(context.Background())
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("Apply = %+v, %v; want success", res, err)
	}

	// Farmer: the sprout's own os/arch and the target, with the JWT.
	if len(f.farmerReqs) != 1 {
		t.Fatalf("farmer got %d requests, want 1", len(f.farmerReqs))
	}
	fr := f.farmerReqs[0]
	if got := fr.URL.Query(); got.Get("os") != "linux" || got.Get("arch") != "amd64" || got.Get("version") != testTarget {
		t.Errorf("manifest query = %v", got)
	}
	if got := fr.Header.Get("Authorization"); got != "Bearer "+testJWT {
		t.Errorf("farmer Authorization = %q, want the gateway JWT", got)
	}

	// Repo: the configured repo + file_name, with no credentials at all
	// (no token configured) and never the JWT.
	if len(f.repoReqs) != 1 {
		t.Fatalf("repo got %d requests, want 1", len(f.repoReqs))
	}
	rr := f.repoReqs[0]
	if rr.URL.Path != "/repo/imasdeb/"+testFileDeb {
		t.Errorf("repo path = %q", rr.URL.Path)
	}
	if got := rr.Header.Get("Authorization"); got != "" {
		t.Errorf("repo request carried Authorization %q, want none", got)
	}
	for k, vs := range rr.Header {
		for _, v := range vs {
			if strings.Contains(v, testJWT) {
				t.Errorf("repo request header %s carries the gateway JWT", k)
			}
		}
	}

	// Installed from the local, verified file; restart only afterwards.
	if len(f.calls) != 1 {
		t.Fatalf("calls before the result was reported = %+v, want only dpkg", f.calls)
	}
	c := f.calls[0]
	if filepath.Base(c.name) != "dpkg" || !slices.Equal(c.args[:3], []string{"--force-confdef", "--force-confold", "-i"}) {
		t.Errorf("installer = %s %q", c.name, c.args)
	}
	if !slices.Contains(c.env, "DEBIAN_FRONTEND=noninteractive") {
		t.Errorf("dpkg env = %q", c.env)
	}
	if filepath.Base(c.args[3]) != testFileDeb || !strings.HasPrefix(c.args[3], filepath.Join(config.CacheDir, stageDirName)) {
		t.Errorf("dpkg installed %q, want the staged %s", c.args[3], testFileDeb)
	}
	f.runDeferred()
	if len(f.calls) != 2 || filepath.Base(f.calls[1].name) != "systemctl" ||
		!slices.Equal(f.calls[1].args, []string{"--no-block", "restart", serviceUnit}) {
		t.Errorf("after the report: %+v, want systemctl --no-block restart %s", f.calls[1:], serviceUnit)
	}
}

func TestApply_InstallerPerPlatform(t *testing.T) {
	cases := []struct {
		name, osRelease, file string
		wantTool              string
		wantArgs              []string
	}{
		{"debian", "ID=debian\n", testFileDeb, "dpkg", []string{"--force-confdef", "--force-confold", "-i"}},
		{"ubuntu", "ID=ubuntu\nID_LIKE=debian\n", testFileDeb, "dpkg", []string{"--force-confdef", "--force-confold", "-i"}},
		{"rhel", "ID=\"rhel\"\nID_LIKE=\"fedora\"\n", testFileRPM, "rpm", []string{"-U"}},
		{"rocky", "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n", testFileRPM, "rpm", []string{"-U"}},
		{"sles", "ID=\"sles\"\nID_LIKE=\"suse\"\n", testFileRPM, "zypper", []string{"--non-interactive", "--no-refresh", "install", "--allow-unsigned-rpm"}},
		{"opensuse", "ID=\"opensuse-leap\"\nID_LIKE=\"suse opensuse\"\n", testFileRPM, "zypper", []string{"--non-interactive", "--no-refresh", "install", "--allow-unsigned-rpm"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			writeFile(t, osReleasePath, []byte(tc.osRelease), 0o644)
			f.manifest.FileName = tc.file
			if res, err := step(t, target(testTarget)).Apply(context.Background()); err != nil || !res.Succeeded {
				t.Fatalf("Apply = %+v, %v", res, err)
			}
			c := f.calls[0]
			n := len(tc.wantArgs)
			if filepath.Base(c.name) != tc.wantTool || !slices.Equal(c.args[:n], tc.wantArgs) || filepath.Base(c.args[n]) != tc.file {
				t.Errorf("installer = %s %q, want %s %q <%s>", c.name, c.args, tc.wantTool, tc.wantArgs, tc.file)
			}
		})
	}
}

func TestApply_WindowsMSI_LaunchesMsiexecDetachedAfterReport(t *testing.T) {
	f := newFixture(t)
	goos = "windows"
	f.manifest.OS, f.manifest.FileName = "windows", testFileMSI

	res, err := step(t, target(testTarget)).Apply(context.Background())
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("Apply = %+v, %v", res, err)
	}
	if q := f.farmerReqs[0].URL.Query(); q.Get("os") != "windows" || q.Get("arch") != "amd64" {
		t.Errorf("manifest query = %v", q)
	}
	if len(f.calls) != 0 || len(f.detached) != 0 {
		t.Fatalf("msiexec ran before the result was reported: calls %+v, detached %+v", f.calls, f.detached)
	}
	f.runDeferred()
	if len(f.detached) != 1 {
		t.Fatalf("detached = %+v, want one msiexec", f.detached)
	}
	d := f.detached[0]
	if d.name != msiexecPath() || !strings.HasSuffix(d.name, filepath.Join("System32", "msiexec.exe")) {
		t.Errorf("msiexec path = %q", d.name)
	}
	if len(d.args) != 6 || d.args[0] != "/i" || d.args[2] != "/qn" || d.args[3] != "/norestart" || d.args[4] != "/l*v" {
		t.Fatalf("msiexec args = %q", d.args)
	}
	// The MSI is still there for msiexec, and is exactly the signed bytes.
	got, err := os.ReadFile(d.args[1])
	if err != nil || sha(got) != f.manifest.ChecksumSHA256 || filepath.Base(d.args[1]) != testFileMSI {
		t.Errorf("staged MSI %q: %v (sha %s)", d.args[1], err, sha(got))
	}
	if len(f.calls) != 0 {
		t.Errorf("Windows ran %+v; want no systemctl", f.calls)
	}
}

// TestRefusals covers every refusal: none of them downloads anything
// or runs an installer.
func TestRefusals(t *testing.T) {
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = otherPub
	cases := []struct {
		name   string
		target string
		setup  func(*fixture)
		want   error
		// wantFarmer: whether farmer is asked at all.
		wantFarmer bool
	}{
		{name: "downgrade", target: "v2.3.9", want: ErrDowngrade},
		{name: "downgrade from prerelease ordering", target: "v2.4.0-rc.1", want: ErrDowngrade},
		{name: "running version unknown", target: testTarget, want: ErrUnknownRunningVersion, setup: func(*fixture) {
			runningVersion = func() (string, error) { return canonicalRunningVersion("(devel)") }
		}},
		{name: "min_sprout_version above running", target: testTarget, wantFarmer: true, want: ErrBelowMinSproutVersion,
			setup: func(f *fixture) { f.manifest.MinSproutVersion = "v2.4.1" }},
		{name: "unsigned manifest", target: testTarget, wantFarmer: true, want: fleetsign.ErrMissingSignature,
			setup: func(f *fixture) {
				m := f.manifest
				b, _ := json.Marshal(m) // Signature ""
				f.rawManifest = b
			}},
		{name: "signed by a key not in the keyring", target: testTarget, wantFarmer: true, want: fleetsign.ErrUnknownKeyVersion,
			setup: func(f *fixture) { f.keyID, f.priv = 2, otherPriv }},
		{name: "signed by the wrong key under a trusted id", target: testTarget, wantFarmer: true, want: fleetsign.ErrInvalidSignature,
			setup: func(f *fixture) { f.priv = otherPriv }},
		{name: "checksum altered after signing", target: testTarget, wantFarmer: true, want: fleetsign.ErrInvalidSignature,
			setup: func(f *fixture) {
				m := f.signed(f.manifest)
				m.ChecksumSHA256 = strings.Repeat("a", 64)
				f.manifest = m
			}},
		{name: "min_sprout_version lowered after signing", target: testTarget, wantFarmer: true, want: fleetsign.ErrInvalidSignature,
			setup: func(f *fixture) {
				f.manifest.MinSproutVersion = "v2.4.1"
				m := f.signed(f.manifest)
				m.MinSproutVersion = "v1.0.0"
				f.manifest = m
			}},
		{name: "manifest for another arch", target: testTarget, wantFarmer: true, want: ErrManifestMismatch,
			setup: func(f *fixture) { f.manifest.Arch = "arm64" }},
		{name: "manifest for another version", target: testTarget, wantFarmer: true, want: ErrManifestMismatch,
			setup: func(f *fixture) { f.manifest.Version = "v2.5.0" }},
		{name: "manifest with an unknown field", target: testTarget, wantFarmer: true, want: fleetsign.ErrInvalidManifest,
			setup: func(f *fixture) {
				b, _ := json.Marshal(f.signed(f.manifest))
				f.rawManifest = append(b[:len(b)-1], []byte(`,"url":"https://evil.example/x.deb"}`)...)
			}},
		{name: "farmer has no manifest", target: testTarget, wantFarmer: true, want: ErrNoManifest,
			setup: func(f *fixture) { f.farmerStatus = http.StatusNotFound }},
		{name: "rpm on a debian sprout", target: testTarget, wantFarmer: true, want: ErrPackageTypeMismatch,
			setup: func(f *fixture) { f.manifest.FileName = testFileRPM }},
		{name: "repo not configured", target: testTarget, wantFarmer: true, want: ErrRepoNotConfigured,
			setup: func(*fixture) { config.SproutUpdateRepoURL = "" }},
		{name: "repo is plain http", target: testTarget, wantFarmer: true, want: ErrRepoNotConfigured,
			setup: func(*fixture) { config.SproutUpdateRepoURL = "http://packages.example.com/imasdeb/" }},
		{name: "keyring missing", target: testTarget, want: os.ErrNotExist,
			setup: func(*fixture) { config.SproutFleetSigningKeyring = filepath.Join(os.TempDir(), "no-such-keyring.json") }},
		{name: "keyring empty", target: testTarget, want: errAny,
			setup: func(*fixture) { writeFile(t, config.SproutFleetSigningKeyring, []byte("{}"), 0o644) }},
		{name: "unsupported OS", target: testTarget, want: ErrUnsupportedPlatform,
			setup: func(*fixture) { goos = "darwin" }},
		{name: "no systemd to restart onto the new version", target: testTarget, want: ErrUnsupportedPlatform,
			setup: func(*fixture) { systemdRunDir = filepath.Join(os.TempDir(), "no-such-systemd-dir") }},
		{name: "installer missing", target: testTarget, want: ErrUnsupportedPlatform,
			setup: func(*fixture) { toolDirs = []string{t.TempDir()} }},
		{name: "farmer not pinned by SproutRootCA", target: testTarget, want: errAny,
			setup: func(f *fixture) {
				_, otherCA := newCAServer(t, http.NotFoundHandler())
				writeFile(t, config.SproutRootCA, otherCA, 0o644)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.setup != nil {
				tc.setup(f)
			}
			for _, run := range []struct {
				name string
				fn   func(context.Context) (cook.Result, error)
			}{{"Apply", step(t, target(tc.target)).Apply}, {"Test", step(t, target(tc.target)).Test}} {
				res, err := run.fn(context.Background())
				if err == nil || res.Succeeded || !res.Failed {
					t.Fatalf("%s = %+v, %v; want a refusal", run.name, res, err)
				}
				if tc.want != errAny && !errors.Is(err, tc.want) {
					t.Errorf("%s error = %v, want %v", run.name, err, tc.want)
				}
			}
			farmer, repo, installs := f.counts()
			if repo != 0 || installs != 0 {
				t.Errorf("refusal reached the repo %d times and installed %d times", repo, installs)
			}
			if !tc.wantFarmer && tc.want != errAny && farmer != 0 {
				t.Errorf("refusal asked farmer %d times; it should be refused first", farmer)
			}
		})
	}
}

// errAny matches any error.
var errAny = errors.New("any error")

func TestParse_RefusesBadTargetVersion(t *testing.T) {
	for _, v := range []any{nil, 241, "", "2.4.1", "v2.4", "v2.4.1+build", "V2.4.1", "v2.4.1 ", "v02.4.1"} {
		props := map[string]interface{}{}
		if v != nil {
			props[fleetsign.PropVersion] = v
		}
		if _, err := (SelfUpdate{}).Parse("id", fleetsign.SelfUpdateMethod, props); err == nil {
			t.Errorf("Parse(version %#v) succeeded", v)
		}
	}
	if _, err := (SelfUpdate{}).Parse("id", "install", target(testTarget)); !errors.Is(err, ErrMethodUndefined) {
		t.Errorf("Parse(method install) = %v", err)
	}
}

func TestApply_SameVersion_NoOp(t *testing.T) {
	f := newFixture(t)
	res, err := step(t, target(testRunning)).Apply(context.Background())
	if err != nil || !res.Succeeded || res.Changed {
		t.Fatalf("Apply = %+v, %v; want unchanged success", res, err)
	}
	if farmer, repo, installs := f.counts(); farmer+repo+installs != 0 {
		t.Errorf("no-op contacted farmer %d, repo %d, installed %d", farmer, repo, installs)
	}
}

func TestApply_HashMismatch_NothingInstalled(t *testing.T) {
	f := newFixture(t)
	f.repoBody = []byte("not the signed package")
	res, err := step(t, target(testTarget)).Apply(context.Background())
	if !errors.Is(err, ErrChecksumMismatch) || res.Succeeded {
		t.Fatalf("Apply = %+v, %v; want ErrChecksumMismatch", res, err)
	}
	if _, repo, installs := f.counts(); repo != 1 || installs != 0 {
		t.Errorf("repo %d, installs %d; want 1 download, no install", repo, installs)
	}
	assertNoStagedFiles(t)
}

func TestApply_TruncatedDownload_NothingInstalled(t *testing.T) {
	f := newFixture(t)
	f.repoBody = pkgBytes[:len(pkgBytes)-1]
	if _, err := step(t, target(testTarget)).Apply(context.Background()); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("Apply error = %v, want ErrChecksumMismatch", err)
	}
	if _, _, installs := f.counts(); installs != 0 {
		t.Errorf("installed %d times", installs)
	}
}

// TestApply_RepoUsesOSTrustStoreNotSproutRootCA: with repoRootCAs nil (the
// OS trust store), a repo whose certificate only SproutRootCA trusts is
// refused.
func TestApply_RepoUsesOSTrustStoreNotSproutRootCA(t *testing.T) {
	f := newFixture(t)
	both := append(append([]byte{}, f.farmerCAPEM...),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.repo.Certificate().Raw})...)
	writeFile(t, config.SproutRootCA, both, 0o644)
	repoRootCAs = nil

	_, err := step(t, target(testTarget)).Apply(context.Background())
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("Apply error = %v, want an x509 unknown authority error for the repo", err)
	}
	if farmer, repo, installs := f.counts(); farmer != 1 || repo != 0 || installs != 0 {
		t.Errorf("farmer %d, repo %d, installs %d; want the manifest only", farmer, repo, installs)
	}
}

func TestApply_RepoToken_BasicAuthToRepoOnly(t *testing.T) {
	f := newFixture(t)
	config.SproutUpdateRepoToken = testRepoToken
	if _, err := step(t, target(testTarget)).Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	user, pass, ok := f.repoReqs[0].BasicAuth()
	if !ok || user != repoUser || pass != testRepoToken {
		t.Errorf("repo basic auth = %q, %q, %v", user, pass, ok)
	}
	if got := f.farmerReqs[0].Header.Get("Authorization"); strings.Contains(got, testRepoToken) || got != "Bearer "+testJWT {
		t.Errorf("farmer Authorization = %q", got)
	}
}

func TestApply_RepoRedirects(t *testing.T) {
	t.Run("to another https host drops the token", func(t *testing.T) {
		f := newFixture(t)
		config.SproutUpdateRepoToken = testRepoToken
		var gotAuth []string
		var mu sync.Mutex
		mirror := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			gotAuth = append(gotAuth, r.Header.Get("Authorization"))
			mu.Unlock()
			w.Write(pkgBytes)
		}))
		defer mirror.Close()
		// Another port is another host: net/http itself would keep the
		// header for the same domain on a different port; CheckRedirect
		// drops it.
		mirrorURL := mirror.URL
		redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, mirrorURL+"/blob", http.StatusFound)
		}))
		defer redirector.Close()
		config.SproutUpdateRepoURL = redirector.URL + "/repo/"
		if _, err := step(t, target(testTarget)).Apply(context.Background()); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if len(gotAuth) != 1 || gotAuth[0] != "" {
			t.Errorf("mirror saw Authorization %q, want none", gotAuth)
		}
		_ = f
	})
	t.Run("to http is refused", func(t *testing.T) {
		f := newFixture(t)
		plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(pkgBytes) }))
		defer plain.Close()
		redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, plain.URL+"/blob", http.StatusFound)
		}))
		defer redirector.Close()
		config.SproutUpdateRepoURL = redirector.URL + "/repo/"
		if _, err := step(t, target(testTarget)).Apply(context.Background()); err == nil || !strings.Contains(err.Error(), "non-https") {
			t.Fatalf("Apply error = %v, want a refused non-https redirect", err)
		}
		if _, _, installs := f.counts(); installs != 0 {
			t.Errorf("installed %d times", installs)
		}
	})
}

func TestApply_FarmerRedirectNotFollowed(t *testing.T) {
	f := newFixture(t)
	f.farmerStatus = http.StatusFound
	_, err := step(t, target(testTarget)).Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("Apply error = %v, want HTTP 302 refused", err)
	}
}

func TestApply_RefreshesRejectedGatewayJWTOnce(t *testing.T) {
	f := newFixture(t)
	f.rejectJWT = testJWT
	if _, err := step(t, target(testTarget)).Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if f.refreshes != 1 || len(f.farmerReqs) != 2 ||
		f.farmerReqs[1].Header.Get("Authorization") != "Bearer "+testJWT+".refreshed" {
		t.Errorf("refreshes %d, farmer requests %d", f.refreshes, len(f.farmerReqs))
	}
}

func TestApply_InstallFailure_ReportedNoRestart(t *testing.T) {
	f := newFixture(t)
	f.failInstall = errors.New("exit status 1")
	res, err := step(t, target(testTarget)).Apply(context.Background())
	if !errors.Is(err, ErrInstallFailed) || res.Succeeded || !res.Failed {
		t.Fatalf("Apply = %+v, %v; want ErrInstallFailed", res, err)
	}
	if !notesContain(res, "dpkg: error processing archive") {
		t.Errorf("notes %v don't carry the installer's output", res.Notes)
	}
	f.runDeferred()
	for _, c := range f.calls {
		if filepath.Base(c.name) == "systemctl" {
			t.Errorf("restarted after a failed install: %+v", c)
		}
	}
	if installed.Load() {
		t.Error("a failed install blocks later updates")
	}
}

func TestApply_ZypperInformationalExitIsSuccess(t *testing.T) {
	f := newFixture(t)
	writeFile(t, osReleasePath, []byte("ID=\"sles\"\n"), 0o644)
	f.manifest.FileName = testFileRPM
	f.failInstall = exitError(t, 102)
	if res, err := step(t, target(testTarget)).Apply(context.Background()); err != nil || !res.Succeeded {
		t.Fatalf("zypper exit 102: Apply = %+v, %v; want success", res, err)
	}

	f2 := newFixture(t)
	writeFile(t, osReleasePath, []byte("ID=\"sles\"\n"), 0o644)
	f2.manifest.FileName = testFileRPM
	f2.failInstall = exitError(t, 104)
	if _, err := step(t, target(testTarget)).Apply(context.Background()); !errors.Is(err, ErrInstallFailed) {
		t.Fatalf("zypper exit 104: Apply error = %v, want ErrInstallFailed", err)
	}
}

func TestApply_OneUpdateUntilRestart(t *testing.T) {
	f := newFixture(t)
	if _, err := step(t, target(testTarget)).Apply(context.Background()); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if _, err := step(t, target(testTarget)).Apply(context.Background()); !errors.Is(err, ErrUpdateInProgress) {
		t.Fatalf("second Apply error = %v, want ErrUpdateInProgress", err)
	}
	if _, repo, _ := f.counts(); repo != 1 {
		t.Errorf("repo got %d requests, want 1", repo)
	}
}

// TestApply_IgnoresUnsignedStepProperties: the pre-FU.2 properties farmer
// still sends are never used; in particular artifact_url isn't fetched.
func TestApply_IgnoresUnsignedStepProperties(t *testing.T) {
	f := newFixture(t)
	var hit bool
	evil := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer evil.Close()
	props := target(testTarget)
	props["artifact_url"] = evil.URL + "/" + testFileDeb
	props[fleetsign.PropChecksumSHA256] = strings.Repeat("0", 64)
	props[fleetsign.PropSignature] = "v1:AAAA"
	if _, err := step(t, props).Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if hit {
		t.Error("the step's artifact_url was fetched")
	}
	if _, repo, _ := f.counts(); repo != 1 {
		t.Errorf("repo got %d requests, want 1", repo)
	}
}

func TestTest_DryRunFetchesNothingButTheManifest(t *testing.T) {
	f := newFixture(t)
	res, err := step(t, target(testTarget)).Test(context.Background())
	if err != nil || !res.Succeeded {
		t.Fatalf("Test = %+v, %v", res, err)
	}
	if farmer, repo, installs := f.counts(); farmer != 1 || repo != 0 || installs != 0 {
		t.Errorf("farmer %d, repo %d, installs %d; want only the manifest", farmer, repo, installs)
	}
	if !notesContain(res, testFileDeb) {
		t.Errorf("notes %v don't name the file", res.Notes)
	}
}

func TestRepoFileURL(t *testing.T) {
	cases := []struct {
		base, want string
		ok         bool
	}{
		{"https://packages.example.com/org/imasdeb/any/", "https://packages.example.com/org/imasdeb/any/f.deb", true},
		{"https://packages.example.com/org/imasdeb/any", "https://packages.example.com/org/imasdeb/any/f.deb", true},
		{"https://mirror.example.com", "https://mirror.example.com/f.deb", true},
		{"https://mirror.example.com:8443/x/", "https://mirror.example.com:8443/x/f.deb", true},
		{"", "", false},
		{"http://mirror.example.com/", "", false},
		{"https:///nohost", "", false},
		{"https://user:pw@mirror.example.com/", "", false},
		{"https://mirror.example.com/?token=x", "", false},
		{"https://mirror.example.com/#x", "", false},
		{"https://mirror.example.com/a\nb", "", false},
		{"ftp://mirror.example.com/", "", false},
	}
	for _, tc := range cases {
		got, err := repoFileURL(tc.base, "f.deb")
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("repoFileURL(%q) = %q, %v; want %q (ok %v)", tc.base, got, err, tc.want, tc.ok)
		}
		if !tc.ok && !errors.Is(err, ErrRepoNotConfigured) {
			t.Errorf("repoFileURL(%q) error %v is not ErrRepoNotConfigured", tc.base, err)
		}
	}
}

func TestOSFamily(t *testing.T) {
	cases := map[string]string{
		"ID=debian\n":                                             "debian",
		"ID=ubuntu\nID_LIKE=debian\n":                             "debian",
		"ID=\"rhel\"\nID_LIKE=\"fedora\"\n":                       "redhat",
		"ID=\"almalinux\"\nID_LIKE=\"rhel centos\"":               "redhat",
		"ID=\"amzn\"\nID_LIKE=\"centos rhel fedora\"":             "redhat",
		"ID=\"sles\"\nID_LIKE=\"suse\"\n":                         "suse",
		"ID=\"opensuse-tumbleweed\"\nID_LIKE=\"opensuse suse\"\n": "suse",
		// SUSE first, even if it also claims fedora.
		"ID=\"sle-micro\"\nID_LIKE=\"suse fedora\"\n": "suse",
		"ID=alpine\n": "",
		"ID=solus\n":  "",
		"garbage":     "",
	}
	dir := t.TempDir()
	for content, want := range cases {
		p := filepath.Join(dir, "os-release")
		writeFile(t, p, []byte(content), 0o644)
		if got := osFamily(p); got != want {
			t.Errorf("osFamily(%q) = %q, want %q", content, got, want)
		}
	}
	if got := osFamily(filepath.Join(dir, "missing")); got != "" {
		t.Errorf("osFamily(missing) = %q", got)
	}
}

func TestDetectPlatform_FallsBackToTools(t *testing.T) {
	newFixture(t)
	osReleasePath = filepath.Join(t.TempDir(), "missing")
	dir := t.TempDir()
	toolDirs = []string{dir}
	if _, err := detectPlatform(); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("no os-release and no tools: %v", err)
	}
	writeFile(t, filepath.Join(dir, "rpm"), []byte("#!/bin/sh\n"), 0o755)
	if p, err := detectPlatform(); err != nil || p.installer != installRPM {
		t.Errorf("rpm only: %+v, %v", p, err)
	}
	writeFile(t, filepath.Join(dir, "dpkg"), []byte("#!/bin/sh\n"), 0o755)
	if p, err := detectPlatform(); err != nil || p.installer != installDpkg {
		t.Errorf("dpkg present: %+v, %v", p, err)
	}
	// A non-executable file is not a tool.
	dir2 := t.TempDir()
	toolDirs = []string{dir2}
	writeFile(t, filepath.Join(dir2, "dpkg"), []byte("#!/bin/sh\n"), 0o644)
	if _, err := detectPlatform(); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("non-executable dpkg: %v", err)
	}
}

func TestCanonicalRunningVersion(t *testing.T) {
	cases := map[string]string{
		"v2.4.1":                               "v2.4.1",
		"v2.4.1+dirty":                         "v2.4.1",
		"v2.5.0-rc.1":                          "v2.5.0-rc.1",
		"v0.0.0-20261001120000-abcdef123456":   "",
		"v0.2.1-0.20261001120000-abcdef123456": "",
		"v0.2.0":                               "v0.2.0",
		"(devel)":                              "",
		"":                                     "",
		"2.4.1":                                "",
	}
	for in, want := range cases {
		got, err := canonicalRunningVersion(in)
		if got != want || (want == "") != (err != nil) {
			t.Errorf("canonicalRunningVersion(%q) = %q, %v; want %q", in, got, err, want)
		}
		if want == "" && !errors.Is(err, ErrUnknownRunningVersion) {
			t.Errorf("canonicalRunningVersion(%q) error %v", in, err)
		}
	}
}

func TestRegistered(t *testing.T) {
	name, methods := SelfUpdate{}.Methods()
	if name != fleetsign.SelfUpdateIngredient || !slices.Equal(methods, []string{fleetsign.SelfUpdateMethod}) {
		t.Fatalf("Methods = %s %v", name, methods)
	}
	props, err := SelfUpdate{}.PropertiesForMethod(fleetsign.SelfUpdateMethod)
	if err != nil || len(props) != 1 {
		t.Fatalf("PropertiesForMethod = %v, %v; want only the version", props, err)
	}
	if _, err := ingredients.NewRecipeCooker(cook.StepID("x"), cook.Ingredient(fleetsign.SelfUpdateIngredient), fleetsign.SelfUpdateMethod, target(testTarget)); err != nil {
		t.Errorf("not registered: %v", err)
	}
}

// --- helpers ---

func notesContain(res cook.Result, s string) bool {
	for _, n := range res.Notes {
		if strings.Contains(n.String(), s) {
			return true
		}
	}
	return false
}

func assertNoStagedFiles(t *testing.T) {
	t.Helper()
	root := filepath.Join(config.CacheDir, stageDirName)
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			t.Errorf("file left behind: %s", p)
		}
		return nil
	})
}

func exitError(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("sh", "-c", fmt.Sprintf("exit %d", code)).Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != code {
		t.Fatalf("making exit status %d: %v", code, err)
	}
	return err
}

func keyringJSON(id int, pub ed25519.PublicKey) []byte {
	return []byte(fmt.Sprintf(`{"%d": %q}`, id, base64.StdEncoding.EncodeToString(pub)))
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func setSeam[T any](t *testing.T, p *T, v T) {
	t.Helper()
	orig := *p
	*p = v
	t.Cleanup(func() { *p = orig })
}

func saveConfig(t *testing.T) {
	t.Helper()
	ca, url, cache, keyring, repo, tok := config.SproutRootCA, config.FarmerURL, config.CacheDir,
		config.SproutFleetSigningKeyring, config.SproutUpdateRepoURL, config.SproutUpdateRepoToken
	t.Cleanup(func() {
		config.SproutRootCA, config.FarmerURL, config.CacheDir = ca, url, cache
		config.SproutFleetSigningKeyring, config.SproutUpdateRepoURL, config.SproutUpdateRepoToken = keyring, repo, tok
	})
}

// newCAServer starts an HTTPS server whose certificate is issued by a new
// CA, and returns it with the CA's PEM.
func newCAServer(t *testing.T, h http.Handler) (*httptest.Server, []byte) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test farmer CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "farmer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(h)
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

// TestShippedKeyring: the keyring the packages install is either the
// fail-closed placeholder {} or a keyring the sprout can load, so a
// malformed key added at release time fails here, not on the fleet.
func TestShippedKeyring(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "packaging", "etc", "fleet-signing-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) == "{}" {
		if _, err := fleetsign.ParseKeyring(data); err == nil {
			t.Fatal("the empty placeholder keyring parsed; it must refuse every update")
		}
		return
	}
	if _, err := fleetsign.ParseKeyring(data); err != nil {
		t.Fatalf("shipped keyring does not parse: %v", err)
	}
}
