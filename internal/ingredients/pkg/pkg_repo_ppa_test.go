package pkg

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gogrlx/snack"
)

func TestPPAArchive(t *testing.T) {
	for in, want := range map[string]string{
		"ppa:deadsnakes/ppa":  "deadsnakes/ppa",
		"ppa:ondrej/php":      "ondrej/php",
		"ppa:git-core":        "git-core/ppa",
		"ppa:a.b+c-d/x.y+z-1": "a.b+c-d/x.y+z-1",
	} {
		o, n, err := ppaArchive(in)
		if err != nil || o+"/"+n != want {
			t.Errorf("%s: %s/%s, %v (want %s)", in, o, n, err, want)
		}
	}
	for _, in := range []string{"ppa:", "ppa:Upper/x", "ppa:a/b/c", "ppa:a b", "ppa:/x"} {
		if _, _, err := ppaArchive(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// noble is what add-apt-repository writes for ppa:deadsnakes/ppa on 24.04.
const noblePPA = `Types: deb
URIs: https://ppa.launchpadcontent.net/deadsnakes/ppa/ubuntu/
Suites: noble
Components: main
Signed-By:
 -----BEGIN PGP PUBLIC KEY BLOCK-----
 .
 -----END PGP PUBLIC KEY BLOCK-----
`

func ppaRig(t *testing.T) *aptRig {
	t.Helper()
	r := newAptRig(t)
	r.snackOK = true
	file := filepath.Join(r.dir, "deadsnakes-ubuntu-ppa-noble.sources")
	r.mock.addRepoHook = func(snack.Repository) {
		if err := os.WriteFile(file, []byte(noblePPA), 0o644); err != nil {
			t.Error(err)
		}
	}
	r.mock.removeRepoHook = func(string) { os.Remove(file) }
	return r
}

func ppaStep(absent bool) Pkg {
	props := map[string]interface{}{"name": "deadsnakes", "url": "ppa:deadsnakes/ppa"}
	if absent {
		props["absent"] = true
	}
	return Pkg{name: "deadsnakes", method: "repo_managed", properties: props}
}

func TestPPACycle(t *testing.T) {
	r := ppaRig(t)
	ctx := context.Background()

	res, err := ppaStep(false).Test(ctx)
	if err != nil || !res.Changed || r.mock.addRepoCalled != nil {
		t.Fatalf("test mode: %+v, %v", res, err)
	}
	res, err = ppaStep(false).Apply(ctx)
	if err != nil || !res.Changed || !res.Succeeded {
		t.Fatalf("add: %+v, %v", res, err)
	}
	if r.mock.addRepoCalled == nil || r.mock.addRepoCalled.URL != "ppa:deadsnakes/ppa" {
		t.Fatalf("snack AddRepo got %+v", r.mock.addRepoCalled)
	}
	r.mock.addRepoCalled = nil
	res, err = ppaStep(false).Apply(ctx)
	if err != nil || res.Changed || r.mock.addRepoCalled != nil {
		t.Fatalf("second cook should find the deb822 source and change nothing: %+v, %v", res, err)
	}
	if r.updates != 0 {
		t.Error("add-apt-repository updates the lists itself; the ingredient must not run apt-get update for a PPA")
	}

	res, err = ppaStep(true).Apply(ctx)
	if err != nil || !res.Changed || r.mock.removeRepoCalled != "ppa:deadsnakes/ppa" {
		t.Fatalf("remove: %+v, %v (RemoveRepo %q)", res, err, r.mock.removeRepoCalled)
	}
	r.mock.removeRepoCalled = ""
	res, err = ppaStep(true).Apply(ctx)
	if err != nil || res.Changed || r.mock.removeRepoCalled != "" {
		t.Fatalf("remove again: %+v, %v", res, err)
	}
}

func TestPPAFoundInOneLineSources(t *testing.T) {
	r := ppaRig(t)
	// An older release's one-line entry on the old host, and a commented
	// one that doesn't count.
	if err := os.WriteFile(aptSourcesList, []byte("# deb http://ppa.launchpad.net/deadsnakes/ppa/ubuntu jammy main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ppaStep(false).Test(context.Background())
	if err != nil || !res.Changed {
		t.Fatalf("a commented entry is not configured: %+v, %v", res, err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "deadsnakes.list"), []byte("deb http://ppa.launchpad.net/deadsnakes/ppa/ubuntu jammy main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = ppaStep(false).Apply(context.Background())
	if err != nil || res.Changed || r.mock.addRepoCalled != nil {
		t.Fatalf("a one-line entry is configured: %+v, %v", res, err)
	}
}

func TestPPAIgnoredFileName(t *testing.T) {
	r := ppaRig(t)
	line := []byte("deb https://ppa.launchpadcontent.net/deadsnakes/ppa/ubuntu noble main\n")
	if err := os.WriteFile(filepath.Join(r.dir, "my repo.list"), line, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ppaStep(false).Apply(context.Background())
	if err != nil || !res.Changed || r.mock.addRepoCalled == nil {
		t.Fatalf("a file apt ignores must not count as configured: %+v, %v", res, err)
	}
}

func TestPPAURIMatch(t *testing.T) {
	src := func(s string, deb822 bool) bool {
		for _, u := range sourceURIs([]byte(s), deb822) {
			if isPPAURI(u, "deadsnakes", "ppa") {
				return true
			}
		}
		return false
	}
	for label, tc := range map[string]struct {
		file   string
		deb822 bool
		want   bool
	}{
		"one-line, new host":           {"deb https://ppa.launchpadcontent.net/deadsnakes/ppa/ubuntu noble main", false, true},
		"one-line, old host":           {"deb http://ppa.launchpad.net/deadsnakes/ppa/ubuntu/ jammy main", false, true},
		"one-line with options":        {"deb [arch=amd64 signed-by=/k.gpg] https://ppa.launchpadcontent.net/deadsnakes/ppa/ubuntu noble main", false, true},
		"one-line, quoted URI":         {`deb "https://ppa.launchpadcontent.net/deadsnakes/ppa/ubuntu" noble main`, false, true},
		"deb822":                       {noblePPA, true, true},
		"deb822 continuation URI":      {"Types: deb\nURIs: https://archive.ubuntu.com/ubuntu\n https://ppa.launchpadcontent.net/deadsnakes/ppa/ubuntu\nSuites: noble\n", true, true},
		"another archive":              {"deb http://ppa.launchpad.net/deadsnakes/ppa2/ubuntu jammy main", false, false},
		"a mirror's path":              {"deb https://mirror.example.org/ppa.launchpad.net/deadsnakes/ppa/ubuntu jammy main", false, false},
		"a lookalike host":             {"deb https://ppa.launchpadcontent.net.example.org/deadsnakes/ppa/ubuntu noble main", false, false},
		"in a comment":                 {"# deb https://ppa.launchpadcontent.net/deadsnakes/ppa/ubuntu noble main", false, false},
		"a suite, not the URI":         {"deb https://archive.ubuntu.com/ubuntu ppa.launchpad.net/deadsnakes/ppa/ubuntu main", false, false},
		"deb822 fields in a .list":     {noblePPA, false, false},
		"a one-line entry in .sources": {"deb https://ppa.launchpadcontent.net/deadsnakes/ppa/ubuntu noble main", true, false},
	} {
		if got := src(tc.file, tc.deb822); got != tc.want {
			t.Errorf("%s: %v, want %v", label, got, tc.want)
		}
	}
}

func TestPPAFailures(t *testing.T) {
	r := ppaRig(t)
	ctx := context.Background()

	lookPath = func(string) (string, error) { return "", errors.New("not found") }
	if _, err := ppaStep(false).Apply(ctx); err == nil || !strings.Contains(err.Error(), "software-properties-common") {
		t.Errorf("missing add-apt-repository: %v", err)
	}
	lookPath = func(string) (string, error) { return "/usr/bin/add-apt-repository", nil }

	r.mock.addRepoErr = errors.New("add-apt-repository: exit status 1: ")
	if res, err := ppaStep(false).Apply(ctx); err == nil || !res.Failed {
		t.Errorf("AddRepo error: %+v, %v", res, err)
	}
	r.mock.addRepoErr = nil

	r.mock.addRepoHook = func(snack.Repository) {}
	if res, err := ppaStep(false).Apply(ctx); err == nil || !strings.Contains(err.Error(), "wrote no source") {
		t.Errorf("AddRepo that wrote nothing: %+v, %v", res, err)
	}
}
