package selfupdate

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
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
	"io"
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

	"github.com/klauspost/compress/zstd"
	"golang.org/x/mod/semver"

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
	// indexSHA is the checksum the repository's indexes list for the
	// package (default: the signed one).
	indexSHA string
	// nupkgEntry is the name the MSI has inside the .nupkg (default: the
	// signed file name).
	nupkgEntry string
	// aptPlainOnly serves the apt index only uncompressed.
	aptPlainOnly bool
	// rpmPrimaryExt is the rpm primary index's compression: ".gz"
	// (default), ".zst", ".xz" or "" (plain XML).
	rpmPrimaryExt *string
	// rpmPrimaryRaw, if set, is served as the primary index verbatim.
	rpmPrimaryRaw []byte
	// aptFilename overrides the Filename the apt index gives.
	aptFilename string

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

	// pkgMeta is what each package says it is, by the SHA-256 of its
	// bytes: what dpkg-deb, rpm -qp and the MSI's Property table report.
	pkgMeta map[string]fakePkg
	// dbInstalled is what the package database reports as installed
	// (dpkg-query, rpm -q): the deb Version or the rpm EPOCH:VERSION-RELEASE.
	// A successful installer run sets it to the package's, unless
	// skipInstall (dpkg --refuse-downgrade or zypper skipping an older
	// package and exiting 0).
	dbInstalled string
	skipInstall bool
	queries     []call
}

// fakePkg is one package's own metadata.
type fakePkg struct {
	name, version, epoch, release       string
	msiName, msiVersion, msiUpgradeCode string
}

// genuinePkg is the metadata of an imas-sprout package built at tag v.
func genuinePkg(v string) fakePkg {
	core, pre, _ := strings.Cut(strings.TrimPrefix(v, "v"), "-")
	ver := core
	if pre != "" {
		ver += "~" + pre
	}
	return fakePkg{name: "imas-sprout", version: ver + "+git", epoch: "(none)", release: "1",
		msiName: "imas sprout", msiVersion: core, msiUpgradeCode: msiUpgradeCode}
}

func (f *fixture) metaOf(file string) (fakePkg, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return fakePkg{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.pkgMeta[sha(b)]
	if !ok {
		return fakePkg{}, errors.New("not a package")
	}
	return m, nil
}

// fakeQuery stands in for dpkg-deb, dpkg-query and rpm.
func (f *fixture) fakeQuery(_ context.Context, name string, args []string) ([]byte, error) {
	f.mu.Lock()
	f.queries = append(f.queries, call{name: name, args: args})
	db := f.dbInstalled
	f.mu.Unlock()
	switch filepath.Base(name) {
	case "dpkg-deb":
		m, err := f.metaOf(args[1])
		if err != nil {
			return nil, err
		}
		return []byte(fmt.Sprintf("Package: %s\nVersion: %s\n", m.name, m.version)), nil
	case "dpkg-query":
		return []byte("install ok installed\n" + db + "\n"), nil
	case "rpm":
		if args[0] == "-qp" {
			m, err := f.metaOf(args[len(args)-1])
			if err != nil {
				return nil, err
			}
			return []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n", m.name, m.epoch, m.version, m.release)), nil
		}
		return []byte(db + "\n"), nil
	}
	return nil, fmt.Errorf("unexpected query tool %s", name)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, keyID: 1, repoBody: pkgBytes,
		pkgMeta: map[string]fakePkg{sha(pkgBytes): genuinePkg(testTarget)}, dbInstalled: "2.4.0+git"}
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
	f.repo = httptest.NewTLSServer(http.HandlerFunc(f.serveRepo))
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
	config.SproutUpdateRepoURL = f.repo.URL + "/imasdeb/any/"
	config.SproutUpdateRepoToken = ""
	config.SproutUpdateRepoFormat, config.SproutUpdateRepoDist, config.SproutUpdateRepoPackageID = "", "", ""

	// Platform: Debian, with fake tools and a running systemd.
	tools := filepath.Join(dir, "bin")
	for _, name := range []string{"dpkg", "dpkg-deb", "dpkg-query", "rpm", "zypper", "systemctl"} {
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
		tool := filepath.Base(name)
		var m fakePkg
		var metaErr error
		if tool != "systemctl" {
			m, metaErr = f.metaOf(args[len(args)-1])
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, call{name, args, env})
		if tool != "systemctl" && !f.skipInstall && metaErr == nil {
			if tool == "dpkg" {
				f.dbInstalled = m.version
			} else {
				f.dbInstalled = m.epoch + ":" + m.version + "-" + m.release
			}
		}
		if tool != "systemctl" && f.failInstall != nil {
			return []byte("dpkg: error processing archive"), f.failInstall
		}
		return []byte("Setting up imas-sprout (2.4.1) ..."), nil
	})
	setSeam(t, &queryCommand, f.fakeQuery)
	setSeam(t, &msiProperties, func(file string, _ []string) (map[string]string, error) {
		m, err := f.metaOf(file)
		if err != nil {
			return nil, err
		}
		return map[string]string{"ProductName": m.msiName, "ProductVersion": m.msiVersion, "UpgradeCode": m.msiUpgradeCode}, nil
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

// serveRepo stands in for the Buildkite registries: an apt repository
// (imasdeb), an rpm repository (imasrpm), a NuGet v3 feed (imasnget) and a
// flat directory, each with its own index. Package files live at paths
// unrelated to their names, as in a real pool, so only reading the index
// finds them.
func (f *fixture) serveRepo(w http.ResponseWriter, r *http.Request) {
	f.record(&f.repoReqs, r)
	sum := f.indexSHA
	if sum == "" {
		sum = sha(pkgBytes)
	}
	name := f.manifest.FileName
	switch r.URL.Path {
	case "/imasdeb/any/dists/any/main/binary-amd64/Packages.gz", "/imasdeb/any/dists/any/main/binary-amd64/Packages":
		gzipped := strings.HasSuffix(r.URL.Path, ".gz")
		if gzipped == f.aptPlainOnly {
			http.NotFound(w, r)
			return
		}
		out := io.Writer(w)
		if gzipped {
			gz := gzip.NewWriter(w)
			defer gz.Close()
			out = gz
		}
		filename := f.aptFilename
		if filename == "" {
			filename = "pool/main/i/imas-sprout/" + name
		}
		fmt.Fprintf(out, "Package: other\nVersion: 1\nFilename: pool/o/other.deb\nSHA256: %s\n\n", strings.Repeat("1", 64))
		fmt.Fprintf(out, "Package: imas-sprout\nVersion: 2.4.1\nDescription: sprout\n continued line\nFilename: %s\nSHA256: %s\n", filename, sum)
	case "/imasdeb/any/pool/main/i/imas-sprout/" + name,
		"/imasrpm/rpm_any/x86_64/Packages/i/" + name,
		"/flat/" + name:
		w.Write(f.repoBody)
	case "/imasrpm/rpm_any/x86_64/repodata/repomd.xml":
		fmt.Fprintf(w, `<?xml version="1.0"?><repomd xmlns="http://linux.duke.edu/metadata/repo">`+
			`<data type="other"><location href="repodata/x-other.xml.gz"/></data>`+
			`<data type="primary"><location href="repodata/abc-primary.xml%s"/></data></repomd>`, f.primaryExt())
	case "/imasrpm/rpm_any/x86_64/repodata/abc-primary.xml" + f.primaryExt():
		if f.rpmPrimaryRaw != nil {
			w.Write(f.rpmPrimaryRaw)
			return
		}
		xmlIndex := fmt.Sprintf(`<?xml version="1.0"?><metadata xmlns="http://linux.duke.edu/metadata/common" packages="2">`+
			`<package type="rpm"><name>other</name><checksum type="sha256" pkgid="YES">%s</checksum><location href="Packages/o/other.rpm"/></package>`+
			`<package type="rpm"><name>imas-sprout</name><checksum type="sha256" pkgid="YES">%s</checksum><location href="Packages/i/%s"/></package>`+
			`</metadata>`, strings.Repeat("2", 64), sum, name)
		switch f.primaryExt() {
		case ".gz":
			gz := gzip.NewWriter(w)
			io.WriteString(gz, xmlIndex)
			gz.Close()
		case ".zst":
			zw, _ := zstd.NewWriter(w)
			io.WriteString(zw, xmlIndex)
			zw.Close()
		default: // "" and ".xz": plain bytes (.xz is refused before reading)
			io.WriteString(w, xmlIndex)
		}
	case "/imasnget/nuget/index.json":
		fmt.Fprintf(w, `{"version":"3.0.0","resources":[{"@id":"%s/imasnget/nuget/query","@type":"SearchQueryService"},`+
			`{"@id":"%s/imasnget/nuget/flat/","@type":"PackageBaseAddress/3.0.0"}]}`, f.repo.URL, f.repo.URL)
	case "/imasnget/nuget/flat/imas.sprout.windows.msi/2.4.1/imas.sprout.windows.msi.2.4.1.nupkg":
		entry := f.nupkgEntry
		if entry == "" {
			entry = name
		}
		zw := zip.NewWriter(w)
		for n, body := range map[string][]byte{"imas.sprout.windows.msi.nuspec": []byte("<package/>"), entry: f.repoBody} {
			fw, _ := zw.Create(n)
			fw.Write(body)
		}
		zw.Close()
	default:
		http.NotFound(w, r)
	}
}

func (f *fixture) primaryExt() string {
	if f.rpmPrimaryExt == nil {
		return ".gz"
	}
	return *f.rpmPrimaryExt
}

// packageReq is the request that downloaded the package itself (or the
// .nupkg), or nil.
func (f *fixture) packageReq() *http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.repoReqs {
		if strings.HasSuffix(r.URL.Path, "/"+f.manifest.FileName) || strings.HasSuffix(r.URL.Path, ".nupkg") {
			return r
		}
	}
	return nil
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
	if got := fr.URL.Query(); got.Get("os") != "linux" || got.Get("arch") != "amd64" ||
		got.Get("package_type") != "deb" || got.Get("version") != testTarget {
		t.Errorf("manifest query = %v", got)
	}
	if got := fr.Header.Get("Authorization"); got != "Bearer "+testJWT {
		t.Errorf("farmer Authorization = %q, want the gateway JWT", got)
	}

	// Repo: the apt index, then the file it names, with no credentials
	// at all (no token configured) and never the JWT.
	var paths []string
	for _, rr := range f.repoReqs {
		paths = append(paths, rr.URL.Path)
		if got := rr.Header.Get("Authorization"); got != "" {
			t.Errorf("repo request %s carried Authorization %q, want none", rr.URL.Path, got)
		}
		for k, vs := range rr.Header {
			for _, v := range vs {
				if strings.Contains(v, testJWT) {
					t.Errorf("repo request header %s carries the gateway JWT", k)
				}
			}
		}
	}
	if want := []string{"/imasdeb/any/dists/any/main/binary-amd64/Packages.gz", "/imasdeb/any/pool/main/i/imas-sprout/" + testFileDeb}; !slices.Equal(paths, want) {
		t.Errorf("repo requests = %q, want %q", paths, want)
	}

	// Installed from the local, verified file; restart only afterwards.
	if len(f.calls) != 1 {
		t.Fatalf("calls before the result was reported = %+v, want only dpkg", f.calls)
	}
	c := f.calls[0]
	if filepath.Base(c.name) != "dpkg" || !slices.Equal(c.args[:4], []string{"--force-confdef", "--force-confold", "--refuse-downgrade", "-i"}) {
		t.Errorf("installer = %s %q", c.name, c.args)
	}
	if !slices.Contains(c.env, "DEBIAN_FRONTEND=noninteractive") {
		t.Errorf("dpkg env = %q", c.env)
	}
	if filepath.Base(c.args[4]) != testFileDeb || !strings.HasPrefix(c.args[4], filepath.Join(config.CacheDir, stageDirName)) {
		t.Errorf("dpkg installed %q, want the staged %s", c.args[4], testFileDeb)
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
		{"debian", "ID=debian\n", testFileDeb, "dpkg", []string{"--force-confdef", "--force-confold", "--refuse-downgrade", "-i"}},
		{"ubuntu", "ID=ubuntu\nID_LIKE=debian\n", testFileDeb, "dpkg", []string{"--force-confdef", "--force-confold", "--refuse-downgrade", "-i"}},
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
			pkg := strings.TrimPrefix(filepath.Ext(tc.file), ".")
			if pkg == "rpm" {
				// The role's rpm baseurl, $basearch left for the sprout.
				config.SproutUpdateRepoURL = f.repo.URL + "/imasrpm/rpm_any/$basearch"
			}
			if res, err := step(t, target(testTarget)).Apply(context.Background()); err != nil || !res.Succeeded {
				t.Fatalf("Apply = %+v, %v", res, err)
			}
			if got := f.farmerReqs[0].URL.Query().Get("package_type"); got != pkg {
				t.Errorf("asked farmer for package_type %q, want %q", got, pkg)
			}
			if f.packageReq() == nil {
				t.Errorf("the package was not fetched from the %s repository", pkg)
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
	config.SproutUpdateRepoURL = f.repo.URL + "/imasnget/nuget/index.json"

	res, err := step(t, target(testTarget)).Apply(context.Background())
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("Apply = %+v, %v", res, err)
	}
	if q := f.farmerReqs[0].URL.Query(); q.Get("os") != "windows" || q.Get("arch") != "amd64" || q.Get("package_type") != "msi" {
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
		{name: "repo not configured", target: testTarget, want: ErrRepoNotConfigured,
			setup: func(*fixture) { config.SproutUpdateRepoURL = "" }},
		{name: "repo is plain http", target: testTarget, want: ErrRepoNotConfigured,
			setup: func(*fixture) { config.SproutUpdateRepoURL = "http://packages.example.com/imasdeb/any/" }},
		{name: "repo format unknown", target: testTarget, want: ErrRepoNotConfigured,
			setup: func(*fixture) { config.SproutUpdateRepoFormat = "yum" }},
		{name: "rpm repo for a deb sprout", target: testTarget, want: ErrRepoNotConfigured,
			setup: func(*fixture) { config.SproutUpdateRepoFormat = "rpm" }},
		{name: "apt dist malformed", target: testTarget, want: ErrRepoNotConfigured,
			setup: func(*fixture) { config.SproutUpdateRepoDist = "any" }},
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
	if _, _, installs := f.counts(); f.packageReq() == nil || installs != 0 {
		t.Errorf("downloaded %v, installs %d; want a download, no install", f.packageReq() != nil, installs)
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
	if len(f.repoReqs) != 2 {
		t.Fatalf("repo got %d requests, want the index and the package", len(f.repoReqs))
	}
	for _, rr := range f.repoReqs {
		user, pass, ok := rr.BasicAuth()
		if !ok || user != repoUser || pass != testRepoToken {
			t.Errorf("repo %s basic auth = %q, %q, %v", rr.URL.Path, user, pass, ok)
		}
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
		config.SproutUpdateRepoURL, config.SproutUpdateRepoFormat = redirector.URL+"/repo/", "flat"
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
		config.SproutUpdateRepoURL, config.SproutUpdateRepoFormat = redirector.URL+"/repo/", "flat"
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
	config.SproutUpdateRepoURL = f.repo.URL + "/imasrpm/rpm_any/x86_64/"
	f.failInstall = exitError(t, 102)
	if res, err := step(t, target(testTarget)).Apply(context.Background()); err != nil || !res.Succeeded {
		t.Fatalf("zypper exit 102: Apply = %+v, %v; want success", res, err)
	}

	f2 := newFixture(t)
	writeFile(t, osReleasePath, []byte("ID=\"sles\"\n"), 0o644)
	f2.manifest.FileName = testFileRPM
	config.SproutUpdateRepoURL = f2.repo.URL + "/imasrpm/rpm_any/x86_64/"
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
	_, before, _ := f.counts()
	if _, err := step(t, target(testTarget)).Apply(context.Background()); !errors.Is(err, ErrUpdateInProgress) {
		t.Fatalf("second Apply error = %v, want ErrUpdateInProgress", err)
	}
	if _, after, _ := f.counts(); after != before {
		t.Errorf("the refused second update reached the repo %d times", after-before)
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
	if f.packageReq() == nil {
		t.Error("the package was not fetched from the configured repo")
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
	format, dist, pkgID := config.SproutUpdateRepoFormat, config.SproutUpdateRepoDist, config.SproutUpdateRepoPackageID
	t.Cleanup(func() {
		config.SproutRootCA, config.FarmerURL, config.CacheDir = ca, url, cache
		config.SproutFleetSigningKeyring, config.SproutUpdateRepoURL, config.SproutUpdateRepoToken = keyring, repo, tok
		config.SproutUpdateRepoFormat, config.SproutUpdateRepoDist, config.SproutUpdateRepoPackageID = format, dist, pkgID
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

// TestSetRunningVersion: cmd/sprout's main.Tag is the running version
// when it is set, validated like any other.
func TestSetRunningVersion(t *testing.T) {
	orig := releaseTag.Load()
	t.Cleanup(func() { releaseTag.Store(orig) })

	SetRunningVersion("v0.3.0")
	if v, err := runningVersion(); err != nil || v != "v0.3.0" {
		t.Errorf("tag v0.3.0: %q, %v", v, err)
	}
	SetRunningVersion("v0.4.0-next") // a goreleaser snapshot tag
	if v, err := runningVersion(); err != nil || v != "v0.4.0-next" {
		t.Errorf("snapshot tag: %q, %v", v, err)
	}
	for _, bad := range []string{"0.3.0", "dev", "v0.0.0-20261001120000-abcdef123456"} {
		SetRunningVersion(bad)
		if v, err := runningVersion(); !errors.Is(err, ErrUnknownRunningVersion) {
			t.Errorf("tag %q: %q, %v; want ErrUnknownRunningVersion", bad, v, err)
		}
	}
	// No tag: the toolchain's stamped version, which in a test binary is
	// not a release version.
	SetRunningVersion("")
	if v, err := runningVersion(); err == nil && semver.Canonical(v) != v {
		t.Errorf("no tag: %q", v)
	}
}

// useRepo points the fixture's sprout at one of its repositories, for
// platform pkg.
func (f *fixture) useRepo(pkg string) {
	switch pkg {
	case "deb":
		config.SproutUpdateRepoURL = f.repo.URL + "/imasdeb/any/"
	case "rpm":
		writeFile(f.t, osReleasePath, []byte("ID=rocky\n"), 0o644)
		f.manifest.FileName = testFileRPM
		config.SproutUpdateRepoURL = f.repo.URL + "/imasrpm/rpm_any/$basearch"
	case "msi":
		goos = "windows"
		f.manifest.OS, f.manifest.FileName = "windows", testFileMSI
		config.SproutUpdateRepoURL = f.repo.URL + "/imasnget/nuget/index.json"
	}
}

func TestApply_RepoFormats_NotInRepo(t *testing.T) {
	for _, pkg := range []string{"deb", "rpm", "msi"} {
		t.Run(pkg, func(t *testing.T) {
			f := newFixture(t)
			f.useRepo(pkg)
			if pkg == "msi" {
				f.nupkgEntry = "something-else.msi"
			} else {
				f.indexSHA = strings.Repeat("3", 64)
			}
			if _, err := step(t, target(testTarget)).Apply(context.Background()); !errors.Is(err, ErrNotInRepo) {
				t.Fatalf("Apply error = %v, want ErrNotInRepo", err)
			}
			if _, _, installs := f.counts(); installs != 0 {
				t.Errorf("installed %d times", installs)
			}
			assertNoStagedFiles(t)
		})
	}
}

// TestApply_RepoFormats_HashMismatch: the index lists the signed
// checksum, but the bytes served aren't the signed ones.
func TestApply_RepoFormats_HashMismatch(t *testing.T) {
	for _, pkg := range []string{"deb", "rpm", "msi"} {
		t.Run(pkg, func(t *testing.T) {
			f := newFixture(t)
			f.useRepo(pkg)
			f.repoBody = []byte("tampered")
			if _, err := step(t, target(testTarget)).Apply(context.Background()); !errors.Is(err, ErrChecksumMismatch) {
				t.Fatalf("Apply error = %v, want ErrChecksumMismatch", err)
			}
			f.runDeferred()
			if _, _, installs := f.counts(); installs != 0 {
				t.Errorf("installed %d times", installs)
			}
			assertNoStagedFiles(t)
		})
	}
}

func TestApply_AptFallsBackToUncompressedIndex(t *testing.T) {
	f := newFixture(t)
	f.aptPlainOnly = true
	if _, err := step(t, target(testTarget)).Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if f.packageReq() == nil {
		t.Error("package not fetched")
	}
}

func TestApply_IndexLocations(t *testing.T) {
	t.Run("non-https location refused", func(t *testing.T) {
		f := newFixture(t)
		f.aptFilename = "http://packages.example.com/" + testFileDeb
		_, err := step(t, target(testTarget)).Apply(context.Background())
		if err == nil || !strings.Contains(err.Error(), "not a plain https URL") {
			t.Fatalf("Apply error = %v, want the location refused", err)
		}
	})
	t.Run("location on another host gets no token", func(t *testing.T) {
		f := newFixture(t)
		config.SproutUpdateRepoToken = testRepoToken
		var auth []string
		var mu sync.Mutex
		mirror := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			auth = append(auth, r.Header.Get("Authorization"))
			mu.Unlock()
			w.Write(pkgBytes)
		}))
		defer mirror.Close()
		f.aptFilename = mirror.URL + "/pool/" + testFileDeb
		if _, err := step(t, target(testTarget)).Apply(context.Background()); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if len(auth) != 1 || auth[0] != "" {
			t.Errorf("other host saw Authorization %q, want none", auth)
		}
		if user, _, ok := f.repoReqs[0].BasicAuth(); !ok || user != repoUser {
			t.Errorf("the configured repo's index request had no token")
		}
	})
}

func TestConfiguredRepo(t *testing.T) {
	deb := platform{os: "linux", arch: "amd64", pkgType: pkgDeb, installer: installDpkg}
	rpm := platform{os: "linux", arch: "arm64", pkgType: pkgRPM, installer: installRPM}
	msi := platform{os: "windows", arch: "amd64", pkgType: pkgMSI, installer: installMsiexec}
	cases := []struct {
		name                   string
		p                      platform
		url, format, dist, pkg string
		wantFormat, wantBase   string
		wantSuite, wantPkg     string
		ok                     bool
	}{
		{name: "apt default", p: deb, url: "https://packages.buildkite.com/yogzblr/imasdeb/any/",
			wantFormat: "apt", wantBase: "https://packages.buildkite.com/yogzblr/imasdeb/any/", wantSuite: "any", ok: true},
		{name: "apt no trailing slash", p: deb, url: "https://packages.buildkite.com/yogzblr/imasdeb/any",
			wantFormat: "apt", wantBase: "https://packages.buildkite.com/yogzblr/imasdeb/any/", wantSuite: "any", ok: true},
		{name: "apt other dist", p: deb, url: "https://m.example.com/debian/", dist: "stable main",
			wantFormat: "apt", wantBase: "https://m.example.com/debian/", wantSuite: "stable", ok: true},
		{name: "rpm basearch", p: rpm, url: "https://packages.buildkite.com/yogzblr/imasrpm/rpm_any/rpm_any/$basearch",
			wantFormat: "rpm", wantBase: "https://packages.buildkite.com/yogzblr/imasrpm/rpm_any/rpm_any/aarch64/", ok: true},
		{name: "nuget default id", p: msi, url: "https://packages.buildkite.com/yogzblr/imasnget/nuget/index.json",
			wantFormat: "nuget", wantBase: "https://packages.buildkite.com/yogzblr/imasnget/nuget/index.json", wantPkg: "imas.sprout.windows.msi", ok: true},
		{name: "nuget own id", p: msi, url: "https://n.example.com/index.json", pkg: "acme.sprout.msi",
			wantFormat: "nuget", wantBase: "https://n.example.com/index.json", wantPkg: "acme.sprout.msi", ok: true},
		{name: "flat for an msi", p: msi, url: "https://m.example.com/msi", format: "flat",
			wantFormat: "flat", wantBase: "https://m.example.com/msi/", ok: true},
		{name: "empty url", p: deb},
		{name: "http", p: deb, url: "http://m.example.com/"},
		{name: "credentials", p: deb, url: "https://u:p@m.example.com/"},
		{name: "query", p: deb, url: "https://m.example.com/?x=1"},
		{name: "fragment", p: deb, url: "https://m.example.com/#x"},
		{name: "control character", p: deb, url: "https://m.example.com/a\nb"},
		{name: "no host", p: deb, url: "https:///x/"},
		{name: "apt for an rpm", p: rpm, url: "https://m.example.com/", format: "apt"},
		{name: "nuget for a deb", p: deb, url: "https://m.example.com/", format: "nuget"},
		{name: "unknown format", p: deb, url: "https://m.example.com/", format: "yum"},
		{name: "dist one field", p: deb, url: "https://m.example.com/", dist: "any"},
		{name: "dist with a slash", p: deb, url: "https://m.example.com/", dist: "any/../x main"},
		{name: "bad nuget id", p: msi, url: "https://n.example.com/index.json", pkg: "../x"},
		{name: "deb on an unknown arch", p: platform{os: "linux", arch: "riscv64", pkgType: pkgDeb}, url: "https://m.example.com/"},
	}
	saveConfig(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config.SproutUpdateRepoURL, config.SproutUpdateRepoFormat = tc.url, tc.format
			config.SproutUpdateRepoDist, config.SproutUpdateRepoPackageID = tc.dist, tc.pkg
			r, err := configuredRepo(tc.p)
			if !tc.ok {
				if err == nil {
					t.Fatalf("accepted: %+v", r)
				}
				if !errors.Is(err, ErrRepoNotConfigured) && !errors.Is(err, ErrUnsupportedPlatform) {
					t.Errorf("error %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.format != tc.wantFormat || r.base.String() != tc.wantBase || r.suite != tc.wantSuite || r.packageID != tc.wantPkg {
				t.Errorf("got format %q base %q suite %q id %q", r.format, r.base, r.suite, r.packageID)
			}
		})
	}
}

func TestRPMLocationFor_XMLBase(t *testing.T) {
	sum := strings.Repeat("a", 64)
	index := `<metadata xmlns="http://linux.duke.edu/metadata/common"><package type="rpm">` +
		`<checksum type="sha256" pkgid="YES">` + strings.ToUpper(sum) + `</checksum>` +
		`<location xml:base="https://cdn.example.com/rpms/" href="Packages/x.rpm"/></package></metadata>`
	href, base, err := rpmLocationFor(strings.NewReader(index), sum)
	if err != nil || href != "Packages/x.rpm" || base != "https://cdn.example.com/rpms/" {
		t.Fatalf("got %q %q %v", href, base, err)
	}
	if href, _, err := rpmLocationFor(strings.NewReader(index), strings.Repeat("b", 64)); err != nil || href != "" {
		t.Fatalf("other sum: %q %v", href, err)
	}
	if _, _, err := rpmLocationFor(strings.NewReader("<metadata><package>"), sum); err == nil {
		t.Fatal("truncated XML accepted")
	}
}

func TestAptFilenameFor(t *testing.T) {
	sum := strings.Repeat("c", 64)
	index := "Package: a\nFilename: pool/a.deb\nSHA256: " + strings.Repeat("d", 64) + "\n\n" +
		"Package: b\nSHA256: " + sum + "\nDescription: x\n Filename: not-this.deb\nFilename: pool/b.deb\n"
	if got, err := aptFilenameFor(strings.NewReader(index), sum); err != nil || got != "pool/b.deb" {
		t.Fatalf("got %q %v", got, err)
	}
	if got, err := aptFilenameFor(strings.NewReader(index), strings.Repeat("e", 64)); err != nil || got != "" {
		t.Fatalf("missing sum: %q %v", got, err)
	}
}

// TestApply_RPMPrimaryIndexCompression: the rpm primary index is read
// gzip-, zstd- (createrepo_c's default since 1.0) or un-compressed; other
// compressions and a corrupt zstd stream are refused, and nothing is
// installed.
func TestApply_RPMPrimaryIndexCompression(t *testing.T) {
	var corruptZstd bytes.Buffer
	zw, _ := zstd.NewWriter(&corruptZstd)
	zw.Write(bytes.Repeat([]byte("<metadata>"), 1000))
	zw.Close()
	corrupt := corruptZstd.Bytes()
	corrupt[len(corrupt)/2] ^= 0xff

	// A valid frame whose header declares a 1 GiB window (Window_Descriptor
	// exponent 20: 2^(10+20)), over maxZstdWindow: refused before the
	// decoder allocates it. One raw, last block holds the content.
	content := []byte("<metadata/>")
	hugeWindow := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 20 << 3}
	bh := 1 | len(content)<<3
	hugeWindow = append(hugeWindow, byte(bh), byte(bh>>8), byte(bh>>16))
	hugeWindow = append(hugeWindow, content...)

	cases := []struct {
		name, ext string
		raw       []byte
		ok        bool
		wantErr   string
	}{
		{name: "gzip", ext: ".gz", ok: true},
		{name: "zstd", ext: ".zst", ok: true},
		{name: "plain", ext: "", ok: true},
		{name: "xz unsupported", ext: ".xz", wantErr: "unsupported index compression .xz"},
		{name: "corrupt zstd", ext: ".zst", raw: corrupt, wantErr: "rpm primary index"},
		{name: "zstd window over the limit", ext: ".zst", raw: hugeWindow, wantErr: "window size exceeded"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.useRepo("rpm")
			ext := tc.ext
			f.rpmPrimaryExt, f.rpmPrimaryRaw = &ext, tc.raw
			_, err := step(t, target(testTarget)).Apply(context.Background())
			if tc.ok {
				if err != nil {
					t.Fatalf("Apply: %v", err)
				}
				if f.packageReq() == nil {
					t.Error("package not fetched")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Apply error = %v, want %q", err, tc.wantErr)
			}
			if _, _, installs := f.counts(); installs != 0 || f.packageReq() != nil {
				t.Errorf("installs %d, package fetched %v", installs, f.packageReq() != nil)
			}
		})
	}
}
