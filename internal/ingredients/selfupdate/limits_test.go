package selfupdate

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/yogzblr/imas/internal/config"
)

// Bounds on a hostile repository (security review I4): every case is
// refused with nothing installed and nothing left staged.

func assertRefusedUninstalled(t *testing.T, f *fixture, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("Apply error = %v, want %v", err, want)
	}
	f.runDeferred()
	if _, _, installs := f.counts(); installs != 0 {
		t.Errorf("installed %d times", installs)
	}
	assertNoStagedFiles(t)
}

// packageRequests counts the repository requests for the package file.
func (f *fixture) packageRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.repoReqs {
		if strings.HasSuffix(r.URL.Path, f.manifest.FileName) || strings.HasSuffix(r.URL.Path, ".nupkg") {
			n++
		}
	}
	return n
}

func TestCurrentLimits(t *testing.T) {
	saveConfig(t)
	config.SproutUpdateMaxIndexBytes, config.SproutUpdateMaxPackageBytes = 0, 0
	config.SproutUpdateRequestTimeout, config.SproutUpdateBudget = 0, 0
	l := currentLimits()
	if l.indexBytes != 16<<20 || l.packageBytes != 512<<20 || l.request != 2*time.Minute || l.budget != 10*time.Minute {
		t.Errorf("defaults = %+v, want 16 MiB, 512 MiB, 2m, 10m", l)
	}
	config.SproutUpdateMaxIndexBytes, config.SproutUpdateMaxPackageBytes = 1<<20, 8<<20
	config.SproutUpdateRequestTimeout, config.SproutUpdateBudget = 30*time.Second, 20*time.Minute
	if l := currentLimits(); l.indexBytes != 1<<20 || l.packageBytes != 8<<20 || l.request != 30*time.Second || l.budget != 20*time.Minute {
		t.Errorf("configured = %+v", l)
	}
	// Never above the ceilings, whatever is set.
	config.SproutUpdateMaxIndexBytes, config.SproutUpdateMaxPackageBytes = 1<<40, 1<<40
	if l := currentLimits(); l.indexBytes != config.DefaultSproutUpdateMaxIndexBytes || l.packageBytes != 512<<20 {
		t.Errorf("over the ceilings = %+v", l)
	}
	l = limits{packageBytes: 100}
	for declared, want := range map[int64]int64{0: 100, 40: 40, 100: 100, 200: 100} {
		if got := l.declaredCap(declared); got != want {
			t.Errorf("declaredCap(%d) = %d, want %d", declared, got, want)
		}
	}
}

// TestApply_IndexLimit: an index over sproutupdatemaxindexbytes is
// refused, whether it is over as downloaded or only once decompressed;
// it is never read as a shorter index cut off at the limit.
func TestApply_IndexLimit(t *testing.T) {
	for name, plain := range map[string]bool{"plain": true, "gzip, decompressed size": false} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			config.SproutUpdateMaxIndexBytes = 64 << 10
			f.aptPlainOnly = plain
			f.aptPadding = 200 << 10
			_, err := step(t, target(testTarget)).Apply(context.Background())
			assertRefusedUninstalled(t, f, err, ErrTooLarge)
			if f.packageRequests() != 0 {
				t.Error("the package was fetched after an oversized index")
			}
		})
	}
	t.Run("within the limit", func(t *testing.T) {
		f := newFixture(t)
		config.SproutUpdateMaxIndexBytes = 1 << 20
		f.aptPadding = 200 << 10
		if res, err := step(t, target(testTarget)).Apply(context.Background()); err != nil || !res.Succeeded {
			t.Fatalf("Apply = %+v, %v", res, err)
		}
	})
	t.Run("rpm primary, zstd", func(t *testing.T) {
		f := newFixture(t)
		f.useRepo("rpm")
		ext := ".zst"
		f.rpmPrimaryExt = &ext
		config.SproutUpdateMaxIndexBytes = 64 << 10
		f.rpmPrimaryRaw = zstdOf(t, []byte(`<?xml version="1.0"?><metadata>`+strings.Repeat("<!-- padding -->", 10<<10)+`</metadata>`))
		_, err := step(t, target(testTarget)).Apply(context.Background())
		assertRefusedUninstalled(t, f, err, ErrTooLarge)
	})
}

func zstdOf(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestApply_PackageLimits: a package is refused above the size its index
// declares, above sproutupdatemaxpackagebytes, and, when the index
// declares more than that limit, before it is requested at all.
func TestApply_PackageLimits(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 1<<20+1)
	for _, pkg := range []string{"deb", "rpm"} {
		t.Run(pkg+": over the declared size", func(t *testing.T) {
			f := newFixture(t)
			f.useRepo(pkg)
			f.declaredSize = int64(len(pkgBytes)) - 1
			_, err := step(t, target(testTarget)).Apply(context.Background())
			assertRefusedUninstalled(t, f, err, ErrTooLarge)
		})
		t.Run(pkg+": declared over the limit, never requested", func(t *testing.T) {
			f := newFixture(t)
			f.useRepo(pkg)
			f.declaredSize = 600 << 20
			_, err := step(t, target(testTarget)).Apply(context.Background())
			assertRefusedUninstalled(t, f, err, ErrTooLarge)
			if f.packageRequests() != 0 {
				t.Error("a package declared over the limit was requested")
			}
		})
		t.Run(pkg+": no declared size, over the configured limit", func(t *testing.T) {
			f := newFixture(t)
			f.useRepo(pkg)
			f.declaredSize = -1
			config.SproutUpdateMaxPackageBytes = 1 << 20
			f.repoBody = big
			f.manifest.ChecksumSHA256, f.indexSHA = sha(big), sha(big)
			f.pkgMeta[sha(big)] = genuinePkg(testTarget)
			_, err := step(t, target(testTarget)).Apply(context.Background())
			assertRefusedUninstalled(t, f, err, ErrTooLarge)
		})
	}
	t.Run("flat: over the configured limit", func(t *testing.T) {
		f := newFixture(t)
		config.SproutUpdateRepoFormat = repoFlat
		config.SproutUpdateRepoURL = f.repo.URL + "/flat/"
		config.SproutUpdateMaxPackageBytes = 1 << 20
		f.repoBody = big
		f.manifest.ChecksumSHA256 = sha(big)
		_, err := step(t, target(testTarget)).Apply(context.Background())
		assertRefusedUninstalled(t, f, err, ErrTooLarge)
	})
	t.Run("msi: the NuGet package over the configured limit", func(t *testing.T) {
		f := newFixture(t)
		f.useRepo("msi")
		config.SproutUpdateMaxPackageBytes = 1 << 20
		// Incompressible, so the .nupkg itself is over the limit.
		f.repoBody = randomBytes(t, 1<<20+1)
		f.manifest.ChecksumSHA256 = sha(f.repoBody)
		_, err := step(t, target(testTarget)).Apply(context.Background())
		assertRefusedUninstalled(t, f, err, ErrTooLarge)
	})
	t.Run("msi: the MSI in the NuGet package declares more than the limit", func(t *testing.T) {
		f := newFixture(t)
		f.useRepo("msi")
		config.SproutUpdateMaxPackageBytes = 1 << 20
		// Compresses to a few KiB, so only the zip entry's size is over.
		f.repoBody = big
		f.manifest.ChecksumSHA256 = sha(big)
		_, err := step(t, target(testTarget)).Apply(context.Background())
		assertRefusedUninstalled(t, f, err, ErrTooLarge)
	})
	t.Run("within the limits", func(t *testing.T) {
		for _, pkg := range []string{"deb", "rpm", "msi"} {
			f := newFixture(t)
			f.useRepo(pkg)
			config.SproutUpdateMaxPackageBytes = 1 << 20
			if res, err := step(t, target(testTarget)).Apply(context.Background()); err != nil || !res.Succeeded {
				t.Fatalf("%s: Apply = %+v, %v", pkg, res, err)
			}
		}
	})
}

// TestWriteVerified_Cap: a download is refused one byte over its cap, and
// nothing is left at its destination.
func TestWriteVerified_Cap(t *testing.T) {
	dir := t.TempDir()
	body := []byte("0123456789")
	if err := writeVerified(bytes.NewReader(body), filepath.Join(dir, "a"), sha(body), 9); !errors.Is(err, ErrTooLarge) {
		t.Errorf("10 bytes under a 9 byte cap: %v, want ErrTooLarge", err)
	}
	if err := writeVerified(bytes.NewReader(body), filepath.Join(dir, "b"), sha(body), 10); err != nil {
		t.Errorf("10 bytes under a 10 byte cap: %v", err)
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "a")); len(matches) != 0 {
		t.Error("the refused download was left behind")
	}
}

// hangPackage makes the repository never answer a request for the
// package, until release is closed or the client gives up.
func hangPackage(f *fixture, release <-chan struct{}) {
	f.repoHook = func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasSuffix(r.URL.Path, f.manifest.FileName) {
			return false
		}
		select {
		case <-release:
			return false
		case <-r.Context().Done():
			return true
		}
	}
}

// TestApply_RequestTimeout: a repository that never answers fails the
// request after sproutupdaterequesttimeout.
func TestApply_RequestTimeout(t *testing.T) {
	f := newFixture(t)
	config.SproutUpdateRequestTimeout = 200 * time.Millisecond
	release := make(chan struct{})
	defer close(release)
	hangPackage(f, release)
	start := time.Now()
	_, err := step(t, target(testTarget)).Apply(context.Background())
	if err == nil || errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("Apply error = %v, want the request timeout", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %v", d)
	}
	assertRefusedUninstalled(t, f, err, err)
}

// TestApply_BudgetReleasesTheLock: an update that has not reached the
// installer when sproutupdatebudget runs out fails with
// ErrBudgetExceeded and releases the update lock, so the next update
// runs.
func TestApply_BudgetReleasesTheLock(t *testing.T) {
	f := newFixture(t)
	config.SproutUpdateRequestTimeout = time.Hour
	config.SproutUpdateBudget = 300 * time.Millisecond
	release := make(chan struct{})
	hangPackage(f, release)

	var wg sync.WaitGroup
	var err error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err = step(t, target(testTarget)).Apply(context.Background())
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the update outlived its budget")
	}
	assertRefusedUninstalled(t, f, err, ErrBudgetExceeded)

	// The hook lets every request through once release is closed.
	close(release)
	config.SproutUpdateBudget = time.Minute
	if res, err := step(t, target(testTarget)).Apply(context.Background()); err != nil || !res.Succeeded {
		t.Fatalf("the next update = %+v, %v; want it to take the released lock and install", res, err)
	}
}

// TestApply_BudgetCoversTheDryRun: Test (the dry run) is bounded by the
// same budget.
func TestApply_BudgetCoversTheDryRun(t *testing.T) {
	f := newFixture(t)
	config.SproutUpdateBudget = 300 * time.Millisecond
	f.farmerRoute = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	})
	_, err := step(t, target(testTarget)).Test(context.Background())
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("Test error = %v, want ErrBudgetExceeded", err)
	}
}
