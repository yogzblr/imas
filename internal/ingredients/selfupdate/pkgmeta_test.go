package selfupdate

// Security review 2026-10, M1 (the signed version bound to the package's
// own metadata, and installers that refuse downgrades) and L2 (no
// presigned redirect URL in a job error). FLAG FOR SECURITY REVIEW.

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/fleetsign"
)

type (
	x509CertPool = x509.CertPool
	urlError     = url.Error
)

// fleetsignManifest is a manifest for version as the fixture signs it.
func fleetsignManifest(version string) fleetsign.Manifest {
	return fleetsign.Manifest{Version: version, OS: "linux", Arch: "amd64", FileName: testFileDeb,
		ChecksumSHA256: sha(pkgBytes), MinSproutVersion: "v2.0.0"}
}

// prodQueryCommand is the real queryCommand, before any fixture swaps it.
var prodQueryCommand = queryCommand

func TestPackageSemver(t *testing.T) {
	for _, tc := range []struct {
		pkgType string
		id      pkgIdentity
		want    string // "" means refused
	}{
		{pkgDeb, pkgIdentity{version: "2.4.1+git"}, "v2.4.1"},
		{pkgDeb, pkgIdentity{version: "2.5.0~rc.1+git"}, "v2.5.0-rc.1"},
		{pkgDeb, pkgIdentity{version: "2.4.1"}, "v2.4.1"},
		{pkgDeb, pkgIdentity{version: "2.4.1+git-1"}, "v2.4.1"},
		{pkgDeb, pkgIdentity{version: "2.4.1+git1"}, "v2.4.1"},
		{pkgDeb, pkgIdentity{version: "1:2.0.0+git"}, ""}, // an epoch outranks every version
		{pkgDeb, pkgIdentity{version: "2.4"}, ""},
		{pkgDeb, pkgIdentity{version: "02.4.1+git"}, ""},
		{pkgDeb, pkgIdentity{version: "2.4.1-rc.1"}, "v2.4.1"}, // a revision, not a prerelease
		{pkgDeb, pkgIdentity{version: "2.4.1 "}, ""},
		{pkgDeb, pkgIdentity{version: ""}, ""},
		{pkgRPM, pkgIdentity{epoch: "(none)", version: "2.4.1+git", release: "1"}, "v2.4.1"},
		{pkgRPM, pkgIdentity{epoch: "0", version: "2.4.1+git", release: "1"}, "v2.4.1"},
		{pkgRPM, pkgIdentity{epoch: "(none)", version: "2.5.0~rc_1+git", release: "1"}, "v2.5.0-rc-1"},
		{pkgRPM, pkgIdentity{epoch: "1", version: "2.0.0+git", release: "1"}, ""},
		{pkgRPM, pkgIdentity{epoch: "(none)", version: "2.4.1-1", release: "1"}, ""},
		{pkgMSI, pkgIdentity{version: "2.4.1"}, "v2.4.1"},
		{pkgMSI, pkgIdentity{version: "2.4.1.0"}, ""},
		{pkgMSI, pkgIdentity{version: "2.4"}, ""},
	} {
		got, err := packageSemver(tc.pkgType, tc.id)
		if tc.want == "" {
			if err == nil || !errors.Is(err, ErrPackageMismatch) {
				t.Errorf("%s %+v = %q, %v; want ErrPackageMismatch", tc.pkgType, tc.id, got, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s %+v = %q, %v; want %s", tc.pkgType, tc.id, got, err, tc.want)
		}
	}
}

func TestManifestComparable(t *testing.T) {
	for _, tc := range [][3]string{
		{pkgDeb, "v2.5.0-rc.1", "v2.5.0-rc.1"},
		{pkgRPM, "v2.4.1", "v2.4.1"},
		{pkgMSI, "v2.5.0-rc.1", "v2.5.0"},
		{pkgMSI, "v2.4.1", "v2.4.1"},
	} {
		if got := manifestComparable(tc[0], tc[1]); got != tc[2] {
			t.Errorf("manifestComparable(%s, %s) = %s, want %s", tc[0], tc[1], got, tc[2])
		}
	}
}

// platformCase is one OS family, the file a manifest names on it and
// its repository.
type platformCase struct {
	name, osRelease, goos, file string
	repo                        func(f *fixture) string
}

var platformCases = []platformCase{
	{"debian dpkg", "ID=debian\n", "linux", testFileDeb, func(f *fixture) string { return f.repo.URL + "/imasdeb/any/" }},
	{"rhel rpm", "ID=\"rhel\"\n", "linux", testFileRPM, func(f *fixture) string { return f.repo.URL + "/imasrpm/rpm_any/$basearch" }},
	{"sles zypper", "ID=\"sles\"\n", "linux", testFileRPM, func(f *fixture) string { return f.repo.URL + "/imasrpm/rpm_any/$basearch" }},
	{"windows msi", "", "windows", testFileMSI, func(f *fixture) string { return f.repo.URL + "/imasnget/nuget/index.json" }},
}

func (pc platformCase) setup(t *testing.T, f *fixture) {
	t.Helper()
	if pc.goos == "windows" {
		goos = "windows"
		f.manifest.OS = "windows"
	} else {
		writeFile(t, osReleasePath, []byte(pc.osRelease), 0o644)
	}
	f.manifest.FileName = pc.file
	config.SproutUpdateRepoURL = pc.repo(f)
}

// TestApply_RefusesOlderGenuinePackage is the M1 scenario: a manifest
// signed for v2.4.1 (above the running v2.4.0, so the manifest-level
// downgrade check passes) whose checksum is that of the genuine, older
// imas-sprout 2.0.0 package the repository still holds. The hash matches
// and the index finds the file, but the package says it is 2.0.0, so
// nothing is installed.
func TestApply_RefusesOlderGenuinePackage(t *testing.T) {
	oldBytes := []byte("!<arch>\ndebian-binary   imas-sprout 2.0.0 (genuine, older)\n")
	for _, pc := range platformCases {
		t.Run(pc.name, func(t *testing.T) {
			f := newFixture(t)
			pc.setup(t, f)
			f.pkgMeta[sha(oldBytes)] = genuinePkg("v2.0.0")
			f.repoBody = oldBytes
			f.indexSHA = sha(oldBytes)
			f.manifest.ChecksumSHA256 = sha(oldBytes)

			res, err := step(t, target(testTarget)).Apply(context.Background())
			if !errors.Is(err, ErrPackageMismatch) || res.Succeeded || !res.Failed {
				t.Fatalf("Apply = %+v, %v; want ErrPackageMismatch", res, err)
			}
			if f.packageReq() == nil {
				t.Fatal("the package was never fetched: the refusal must come from its metadata, after the hash check")
			}
			f.runDeferred()
			if _, _, installs := f.counts(); installs != 0 {
				t.Errorf("installed %d times; calls %+v detached %+v", installs, f.calls, f.detached)
			}
			for _, c := range f.calls {
				if filepath.Base(c.name) == "systemctl" {
					t.Errorf("restarted after a refusal: %+v", c)
				}
			}
			assertNoStagedFiles(t)
			if installed.Load() {
				t.Error("a refused package blocks later updates")
			}
		})
	}
}

// TestApply_RefusesPackageMetadataMismatch: other packages whose bytes a
// signed checksum could name.
func TestApply_RefusesPackageMetadataMismatch(t *testing.T) {
	for name, meta := range map[string]fakePkg{
		"another package in the mirror": {name: "openssl", version: "2.4.1+git", epoch: "(none)", release: "1",
			msiName: "OpenSSL", msiVersion: "2.4.1", msiUpgradeCode: "{00000000-0000-0000-0000-000000000001}"},
		"newer than the manifest": genuinePkg("v2.5.0"),
		// An MSI can't tell (TestApply_PrereleaseVersions), so this case
		// runs for deb and rpm only.
		"prerelease of the target": genuinePkg("v2.4.1-rc.1"),
		"with an epoch":            func() fakePkg { p := genuinePkg(testTarget); p.version = "1:" + p.version; p.epoch = "1"; return p }(),
	} {
		for _, pc := range platformCases {
			t.Run(name+"/"+pc.name, func(t *testing.T) {
				if (name == "prerelease of the target" || name == "with an epoch") && pc.goos == "windows" {
					t.Skip("an MSI ProductVersion carries no prerelease or epoch")
				}
				f := newFixture(t)
				pc.setup(t, f)
				f.pkgMeta[sha(pkgBytes)] = meta
				if _, err := step(t, target(testTarget)).Apply(context.Background()); !errors.Is(err, ErrPackageMismatch) {
					t.Fatalf("Apply error = %v, want ErrPackageMismatch", err)
				}
				f.runDeferred()
				if _, _, installs := f.counts(); installs != 0 {
					t.Errorf("installed %d times", installs)
				}
			})
		}
	}
}

// A prerelease installs on Linux, where the package's metadata carries
// the prerelease and is compared in full.
func TestApply_PrereleaseVersions(t *testing.T) {
	for _, pc := range platformCases[:3] {
		t.Run(pc.name, func(t *testing.T) {
			f := newFixture(t)
			pc.setup(t, f)
			f.manifest.Version = "v2.5.0-rc.1"
			f.pkgMeta[sha(pkgBytes)] = genuinePkg("v2.5.0-rc.1")
			res, err := step(t, target("v2.5.0-rc.1")).Apply(context.Background())
			if err != nil || !res.Succeeded {
				t.Fatalf("Apply = %+v, %v", res, err)
			}
			if !notesContain(res, "matches the signed manifest") {
				t.Errorf("notes %v don't record the metadata check", res.Notes)
			}
			if _, _, installs := f.counts(); installs != 1 {
				t.Errorf("installed %d times, want 1", installs)
			}
		})
	}
	t.Run("msi identity", func(t *testing.T) {
		p := platform{os: "windows", arch: "amd64", pkgType: pkgMSI, installer: installMsiexec}
		setSeam(t, &msiProperties, func(string, []string) (map[string]string, error) {
			return map[string]string{"ProductName": msiProductName, "ProductVersion": "2.5.0", "UpgradeCode": strings.ToLower(msiUpgradeCode)}, nil
		})
		// A prerelease manifest is refused for an MSI, even though the
		// MSI's ProductVersion (2.5.0) matches its MAJOR.MINOR.PATCH.
		if _, _, err := verifyPackageIdentity(context.Background(), p, "x.msi", fleetsignManifest("v2.5.0-rc.1")); !errors.Is(err, ErrPrereleaseOnWindows) {
			t.Errorf("rc manifest, 2.5.0 MSI: %v, want ErrPrereleaseOnWindows", err)
		}
		if _, _, err := verifyPackageIdentity(context.Background(), p, "x.msi", fleetsignManifest("v2.5.0")); err != nil {
			t.Errorf("v2.5.0 manifest, 2.5.0 MSI: %v", err)
		}
		if _, _, err := verifyPackageIdentity(context.Background(), p, "x.msi", fleetsignManifest("v2.5.1")); !errors.Is(err, ErrPackageMismatch) {
			t.Errorf("v2.5.1 manifest, 2.5.0 MSI: %v, want ErrPackageMismatch", err)
		}
	})
}

// TestApply_PrereleaseRefusedOnWindows: a prerelease target on a Windows
// sprout is refused before farmer or the repository is asked anything,
// by both Apply and the dry run. A release version on Windows still
// installs.
func TestApply_PrereleaseRefusedOnWindows(t *testing.T) {
	for _, v := range []string{"v2.5.0-rc.1", "v2.4.1-0.beta"} {
		t.Run(v, func(t *testing.T) {
			f := newFixture(t)
			platformCases[3].setup(t, f)
			f.manifest.Version = v
			f.pkgMeta[sha(pkgBytes)] = genuinePkg(v)
			for name, run := range map[string]func(context.Context) (cook.Result, error){
				"Apply": step(t, target(v)).Apply, "Test": step(t, target(v)).Test,
			} {
				res, err := run(context.Background())
				if !errors.Is(err, ErrPrereleaseOnWindows) || res.Succeeded || !res.Failed {
					t.Fatalf("%s = %+v, %v; want ErrPrereleaseOnWindows", name, res, err)
				}
			}
			f.runDeferred()
			if farmer, repo, installs := f.counts(); farmer != 0 || repo != 0 || installs != 0 {
				t.Errorf("farmer %d, repo %d, installs %d; want nothing fetched or installed", farmer, repo, installs)
			}
			assertNoStagedFiles(t)
		})
	}
	t.Run("release still installs", func(t *testing.T) {
		f := newFixture(t)
		platformCases[3].setup(t, f)
		if res, err := step(t, target(testTarget)).Apply(context.Background()); err != nil || !res.Succeeded {
			t.Fatalf("Apply = %+v, %v", res, err)
		}
		f.runDeferred()
		if len(f.detached) != 1 {
			t.Errorf("msiexec started %d times, want 1", len(f.detached))
		}
	})
}

// TestApply_InstallerSkippedTheDowngrade: dpkg --refuse-downgrade and
// zypper (without --oldpackage) refuse an older package by skipping it and
// exiting 0. The sprout reads the installed version back and fails the
// step rather than reporting an install that didn't happen, and schedules
// no restart.
func TestApply_InstallerSkippedThePackage(t *testing.T) {
	for _, pc := range platformCases[:3] {
		t.Run(pc.name, func(t *testing.T) {
			f := newFixture(t)
			pc.setup(t, f)
			f.skipInstall = true
			res, err := step(t, target(testTarget)).Apply(context.Background())
			if !errors.Is(err, ErrInstallFailed) || res.Succeeded {
				t.Fatalf("Apply = %+v, %v; want ErrInstallFailed", res, err)
			}
			if !strings.Contains(err.Error(), "2.4.0") {
				t.Errorf("error %q doesn't say what is installed", err)
			}
			f.runDeferred()
			for _, c := range f.calls {
				if filepath.Base(c.name) == "systemctl" {
					t.Errorf("restarted after a skipped install: %+v", c)
				}
			}
			if installed.Load() {
				t.Error("a skipped install blocks later updates")
			}
		})
	}
}

// TestApply_ZypperGetsNoOldPackage pins that zypper is never told to
// accept an older package.
func TestApply_ZypperGetsNoOldPackage(t *testing.T) {
	f := newFixture(t)
	platformCases[2].setup(t, f)
	if _, err := step(t, target(testTarget)).Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, c := range f.calls {
		for _, a := range c.args {
			if a == "--oldpackage" || a == "--force" {
				t.Errorf("zypper called with %s: %q", a, c.args)
			}
		}
	}
}

func TestApply_MetadataToolMissingRefusedBeforeDownload(t *testing.T) {
	f := newFixture(t)
	os.Remove(filepath.Join(toolDirs[0], "dpkg-deb"))
	if _, err := step(t, target(testTarget)).Apply(context.Background()); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("Apply error = %v, want ErrUnsupportedPlatform", err)
	}
	if _, repo, _ := f.counts(); repo != 0 {
		t.Errorf("the repository was asked %d times", repo)
	}
}

func TestControlFields(t *testing.T) {
	if got, err := controlFields("Package: imas-sprout\nVersion: 2.4.1+git\n", "Package", "Version"); err != nil ||
		got["Package"] != "imas-sprout" || got["Version"] != "2.4.1+git" {
		t.Errorf("got %v, %v", got, err)
	}
	for _, out := range []string{
		"Package: imas-sprout\n",                                        // no Version
		"Package: imas-sprout\nVersion: 2.4.1\nVersion: 2.0.0\n",        // twice
		"Package: imas-sprout\nVersion: 2.4.1\n continued\n",            // multi-line
		"Package: imas-sprout\nVersion: 2.4.1\nDescription: x\n",        // unexpected
		"Package: imas-sprout\nVersion: \n",                             // empty
		"dpkg-deb: warning: ignoring\nPackage: a\nVersion: 2.4.1+git\n", // anything else
	} {
		if _, err := controlFields(out, "Package", "Version"); !errors.Is(err, ErrPackageMismatch) {
			t.Errorf("%q: %v, want ErrPackageMismatch", out, err)
		}
	}
}

// TestReadPackageIdentity_RealDpkgDeb runs the real dpkg-deb on real
// .deb files built the way nfpm writes their versions. It is skipped
// where dpkg-deb isn't installed.
func TestReadPackageIdentity_RealDpkgDeb(t *testing.T) {
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("dpkg-deb not installed")
	}
	setSeam(t, &queryCommand, prodQueryCommand)
	setSeam(t, &toolDirs, []string{"/usr/bin", "/bin"})
	p := platform{os: "linux", arch: "amd64", pkgType: pkgDeb, installer: installDpkg}
	for _, tc := range []struct{ name, version, want string }{
		{"imas-sprout", "2.4.1+git", "v2.4.1"},
		{"imas-sprout", "2.5.0~rc.1+git", "v2.5.0-rc.1"},
		{"imas-sprout", "2.0.0+git", "v2.0.0"},
		{"openssl", "2.4.1+git", "v2.4.1"},
	} {
		dir := t.TempDir()
		root := filepath.Join(dir, "pkg")
		writeFile(t, filepath.Join(root, "DEBIAN", "control"), []byte("Package: "+tc.name+"\nVersion: "+tc.version+
			"\nArchitecture: amd64\nMaintainer: imas <imas@example.com>\nDescription: test\n"), 0o644)
		writeFile(t, filepath.Join(root, "usr", "bin", "imas-sprout"), []byte("#!/bin/sh\n"), 0o755)
		deb := filepath.Join(dir, "x.deb")
		if out, err := exec.Command("dpkg-deb", "--root-owner-group", "-b", root, deb).CombinedOutput(); err != nil {
			t.Fatalf("dpkg-deb -b: %v: %s", err, out)
		}
		id, err := readPackageIdentity(context.Background(), p, deb)
		if err != nil || id.name != tc.name || id.version != tc.version {
			t.Fatalf("%s %s: got %+v, %v", tc.name, tc.version, id, err)
		}
		if v, err := packageSemver(pkgDeb, id); err != nil || v != tc.want {
			t.Errorf("%s: packageSemver = %s, %v; want %s", tc.version, v, err, tc.want)
		}
		_, _, err = verifyPackageIdentity(context.Background(), p, deb, fleetsignManifest(testTarget))
		if wantOK := tc.name == "imas-sprout" && tc.want == testTarget; (err == nil) != wantOK {
			t.Errorf("%s %s against a %s manifest: %v", tc.name, tc.version, testTarget, err)
		}
	}
	// Not a package at all.
	junk := filepath.Join(t.TempDir(), "junk.deb")
	writeFile(t, junk, []byte("not an ar archive"), 0o600)
	if _, err := readPackageIdentity(context.Background(), p, junk); err == nil {
		t.Error("dpkg-deb accepted a non-package")
	}
}

// TestApply_RedirectURLsNeverReachTheError (L2): a repository that
// redirects to a presigned URL must not get that URL's query, which holds
// its signature, into the step's error.
func TestApply_RedirectURLsNeverReachTheError(t *testing.T) {
	const secret = "X-Amz-Signature=deadbeefSECRET&X-Amz-Credential=AKIAEXAMPLE"
	closed := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		l.Close()
		return addr
	}()
	for name, location := range map[string]string{
		"to a host that refuses the connection": "https://" + closed + "/blob/pkg.deb?" + secret,
		"to plain http":                         "http://cdn.example.invalid/blob/pkg.deb?" + secret,
		"to an unparseable location":            "https://cdn.example.invalid/%zz/pkg.deb?" + secret,
		"with a fragment":                       "https://" + closed + "/blob#" + secret,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", location)
				w.WriteHeader(http.StatusFound)
			}))
			defer redirector.Close()
			setSeam(t, &repoRootCAs, func() *x509CertPool {
				pool := repoRootCAs.Clone()
				pool.AddCert(redirector.Certificate())
				return pool
			}())
			config.SproutUpdateRepoURL, config.SproutUpdateRepoFormat = redirector.URL+"/repo/", "flat"
			res, err := step(t, target(testTarget)).Apply(context.Background())
			if err == nil {
				t.Fatal("Apply succeeded")
			}
			for _, leak := range []string{"SECRET", "X-Amz", "AKIA"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("error leaks %s: %v", leak, err)
				}
				for _, n := range res.Notes {
					if strings.Contains(n.String(), leak) {
						t.Errorf("note leaks %s: %s", leak, n)
					}
				}
			}
			if !strings.Contains(err.Error(), "/repo/") {
				t.Errorf("error %q no longer says which request failed", err)
			}
			if _, _, installs := f.counts(); installs != 0 {
				t.Errorf("installed %d times", installs)
			}
		})
	}
}

func TestRedactedError(t *testing.T) {
	if redactedError(nil) != nil {
		t.Error("nil became an error")
	}
	inner := errors.New("connection refused")
	ue := &urlError{Op: "Get", URL: "https://user:pw@cdn.example.com/a/b?sig=SECRET#frag", Err: inner}
	err := redactedError(ue)
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "pw") || strings.Contains(err.Error(), "frag") {
		t.Errorf("redacted error = %q", err)
	}
	if !errors.Is(err, inner) {
		t.Error("the chain was lost")
	}
	var got *urlError
	if !errors.As(err, &got) || got.URL != "https://cdn.example.com/a/b" {
		t.Errorf("url.Error in the chain = %+v", got)
	}
}
