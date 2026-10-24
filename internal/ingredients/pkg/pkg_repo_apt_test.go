package pkg

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const aptHeader = "# Managed by imas pkg.repo_managed (%s); local changes are overwritten.\n"

func TestAptSourceText(t *testing.T) {
	tests := []struct {
		label, url, file, body string
	}{
		{
			"flat repository with trusted=yes",
			"deb [trusted=yes] file:/var/tmp/imas-uat-repo-x ./",
			"r.list", "deb [trusted=yes] file:/var/tmp/imas-uat-repo-x ./\n",
		},
		{
			"signed-by and arch",
			"deb [arch=amd64 signed-by=/etc/apt/keyrings/r.gpg] https://repo.example.com/ubuntu noble main contrib",
			"r.list", "deb [arch=amd64 signed-by=/etc/apt/keyrings/r.gpg] https://repo.example.com/ubuntu noble main contrib\n",
		},
		{
			"spaced option list and deb-src",
			"  deb [ trusted=yes ] http://repo.example.com/debian bookworm main\ndeb-src http://repo.example.com/debian bookworm main  \n",
			"r.list", "deb [ trusted=yes ] http://repo.example.com/debian bookworm main\ndeb-src http://repo.example.com/debian bookworm main\n",
		},
		{
			"plain entry",
			"deb http://archive.ubuntu.com/ubuntu noble universe",
			"r.list", "deb http://archive.ubuntu.com/ubuntu noble universe\n",
		},
		{
			"deb822",
			"Types: deb\nURIs: https://repo.example.com/ubuntu\nSuites: noble\nComponents: main\nSigned-By: /etc/apt/keyrings/r.gpg\n",
			"r.sources", "Types: deb\nURIs: https://repo.example.com/ubuntu\nSuites: noble\nComponents: main\nSigned-By: /etc/apt/keyrings/r.gpg\n",
		},
		{
			"deb822 flat, two stanzas",
			"Types: deb\nURIs: file:/srv/a\nSuites: ./\nTrusted: yes\n\nTypes: deb\nURIs: file:/srv/b\nSuites: ./\n",
			"r.sources", "Types: deb\nURIs: file:/srv/a\nSuites: ./\nTrusted: yes\n\nTypes: deb\nURIs: file:/srv/b\nSuites: ./\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			file, body, err := aptSource("r", tt.url)
			if err != nil {
				t.Fatal(err)
			}
			if file != tt.file {
				t.Errorf("file = %q, want %q", file, tt.file)
			}
			want := strings.Replace(aptHeader, "%s", "r", 1) + tt.body
			if string(body) != want {
				t.Errorf("body =\n%s\nwant\n%s", body, want)
			}
		})
	}
}

func TestAptSourceRejects(t *testing.T) {
	tests := []struct {
		label, name, url, want string
	}{
		{"empty url", "r", "  ", "needs a url"},
		{"ppa shortcut", "r", "ppa:deadsnakes/ppa", "must start with deb"},
		{"bare url", "r", "https://repo.example.com", "must start with deb"},
		{"no suite", "r", "deb https://repo.example.com", "needs a URI and a suite"},
		{"no component", "r", "deb https://repo.example.com noble", "at least one component"},
		{"flat with component", "r", "deb file:/srv/r ./ main", "takes no components"},
		{"unclosed options", "r", "deb [trusted=yes file:/srv/r ./", "no closing ]"},
		{"bad option", "r", "deb [trusted] file:/srv/r ./", "not key=value"},
		{"no scheme", "r", "deb /srv/r ./", "no scheme"},
		{"deb822 without URIs", "r", "Types: deb\nSuites: noble\nComponents: main", "no uris field"},
		{"name with slash", "../r", "deb file:/srv/r ./", "only letters"},
		{"name with space", "my repo", "deb file:/srv/r ./", "only letters"},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			_, _, err := aptSource(tt.name, tt.url)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// aptRig points repo_managed at an apt mock, a temporary sources
// directory and a stub apt-get update.
type aptRig struct {
	dir     string
	updates int
	err     error
}

func newAptRig(t *testing.T) *aptRig {
	t.Helper()
	r := &aptRig{dir: t.TempDir()}
	mock := newMock()
	mock.name = "apt"
	restore := withManager(mock)
	origDir, origUpdate := aptSourcesDir, aptUpdate
	aptSourcesDir = r.dir
	aptUpdate = func(context.Context) error { r.updates++; return r.err }
	t.Cleanup(func() {
		restore()
		aptSourcesDir, aptUpdate = origDir, origUpdate
	})
	t.Cleanup(func() {
		if mock.addRepoCalled != nil || mock.removeRepoCalled != "" {
			t.Error("apt repositories must not go through snack's AddRepo/RemoveRepo")
		}
	})
	return r
}

func (r *aptRig) read(t *testing.T, base string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.dir, base))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (r *aptRig) exists(base string) bool {
	_, err := os.Stat(filepath.Join(r.dir, base))
	return err == nil
}

func repoStep(url string, absent bool) Pkg {
	props := map[string]interface{}{"name": "imas-uat-x", "url": url}
	if absent {
		props["absent"] = true
	}
	return Pkg{name: "imas-uat-x", method: "repo_managed", properties: props}
}

const flatURL = "deb [trusted=yes] file:/var/tmp/imas-uat-repo-x ./"

func TestAptRepoManagedIdempotent(t *testing.T) {
	r := newAptRig(t)
	ctx := context.Background()

	res, err := repoStep(flatURL, false).Apply(ctx)
	if err != nil || !res.Changed || !res.Succeeded {
		t.Fatalf("first cook: %+v, %v", res, err)
	}
	if got := r.read(t, "imas-uat-x.list"); !strings.HasSuffix(got, flatURL+"\n") {
		t.Errorf("source file = %q", got)
	}
	if info, _ := os.Stat(filepath.Join(r.dir, "imas-uat-x.list")); info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644", info.Mode().Perm())
	}
	if r.updates != 1 {
		t.Errorf("apt-get update ran %d times, want 1", r.updates)
	}

	res, err = repoStep(flatURL, false).Apply(ctx)
	if err != nil || res.Changed || !res.Succeeded {
		t.Fatalf("second cook: %+v, %v", res, err)
	}
	if r.updates != 1 {
		t.Errorf("an unchanged repository ran apt-get update")
	}

	newURL := "deb [trusted=yes] file:/var/tmp/imas-uat-repo-y ./"
	res, err = repoStep(newURL, false).Test(ctx)
	if err != nil || !res.Changed {
		t.Fatalf("test cook of a changed url: %+v, %v", res, err)
	}
	if got := r.read(t, "imas-uat-x.list"); !strings.HasSuffix(got, flatURL+"\n") {
		t.Errorf("test mode wrote the file: %q", got)
	}
	res, err = repoStep(newURL, false).Apply(ctx)
	if err != nil || !res.Changed {
		t.Fatalf("changed url: %+v, %v", res, err)
	}
	if got := r.read(t, "imas-uat-x.list"); !strings.HasSuffix(got, newURL+"\n") {
		t.Errorf("source file not updated: %q", got)
	}
	if r.updates != 2 {
		t.Errorf("apt-get update ran %d times, want 2", r.updates)
	}
}

func TestAptRepoManagedTestModeWritesNothing(t *testing.T) {
	r := newAptRig(t)
	res, err := repoStep(flatURL, false).Test(context.Background())
	if err != nil || !res.Changed || !res.Succeeded {
		t.Fatalf("%+v, %v", res, err)
	}
	if r.exists("imas-uat-x.list") || r.updates != 0 {
		t.Error("test mode changed the system")
	}
}

func TestAptRepoManagedFormatSwitch(t *testing.T) {
	r := newAptRig(t)
	ctx := context.Background()
	if _, err := repoStep(flatURL, false).Apply(ctx); err != nil {
		t.Fatal(err)
	}
	deb822 := "Types: deb\nURIs: file:/var/tmp/imas-uat-repo-x\nSuites: ./\nTrusted: yes"
	res, err := repoStep(deb822, false).Apply(ctx)
	if err != nil || !res.Changed {
		t.Fatalf("%+v, %v", res, err)
	}
	if r.exists("imas-uat-x.list") || !r.exists("imas-uat-x.sources") {
		t.Error("switching to deb822 should replace the .list with a .sources file")
	}
}

func TestAptRepoManagedUpdateFailureReverts(t *testing.T) {
	r := newAptRig(t)
	ctx := context.Background()
	if _, err := repoStep(flatURL, false).Apply(ctx); err != nil {
		t.Fatal(err)
	}
	before := r.read(t, "imas-uat-x.list")
	r.err = errors.New("apt-get: exit status 100; stderr: E: broken; stdout: (empty)")

	res, err := repoStep("deb [trusted=yes] file:/var/tmp/elsewhere ./", false).Apply(ctx)
	if err == nil || !res.Failed {
		t.Fatalf("expected failure, got %+v", res)
	}
	if !strings.Contains(err.Error(), "E: broken") {
		t.Errorf("error should carry apt-get's output: %v", err)
	}
	if got := r.read(t, "imas-uat-x.list"); got != before {
		t.Errorf("file not restored: %q", got)
	}

	// A new repository whose update fails leaves no file behind.
	res, err = Pkg{name: "other", method: "repo_managed", properties: map[string]interface{}{
		"name": "other", "url": flatURL,
	}}.Apply(ctx)
	if err == nil || r.exists("other.list") {
		t.Errorf("new source kept after failed update: %+v, %v", res, err)
	}
}

func TestAptRepoManagedRemove(t *testing.T) {
	r := newAptRig(t)
	ctx := context.Background()
	if _, err := repoStep(flatURL, false).Apply(ctx); err != nil {
		t.Fatal(err)
	}

	res, err := repoStep("", true).Test(ctx)
	if err != nil || !res.Changed || !r.exists("imas-uat-x.list") {
		t.Fatalf("test-mode remove: %+v, %v", res, err)
	}

	res, err = repoStep("", true).Apply(ctx)
	if err != nil || !res.Changed || !res.Succeeded {
		t.Fatalf("remove: %+v, %v", res, err)
	}
	if r.exists("imas-uat-x.list") {
		t.Error("source file still present")
	}
	if r.updates != 2 {
		t.Errorf("apt-get update ran %d times, want 2", r.updates)
	}

	res, err = repoStep("", true).Apply(ctx)
	if err != nil || res.Changed || !res.Succeeded {
		t.Fatalf("remove again: %+v, %v", res, err)
	}
	if r.updates != 2 {
		t.Error("removing an absent repository ran apt-get update")
	}
}

func TestAptRepoManagedRemoveUpdateFailure(t *testing.T) {
	r := newAptRig(t)
	ctx := context.Background()
	if _, err := repoStep(flatURL, false).Apply(ctx); err != nil {
		t.Fatal(err)
	}
	r.err = errors.New("boom")
	res, err := repoStep("", true).Apply(ctx)
	if err == nil || !res.Failed || !res.Changed {
		t.Fatalf("expected a failed, changed result: %+v, %v", res, err)
	}
	if r.exists("imas-uat-x.list") {
		t.Error("removal should stand even when apt-get update fails")
	}
}

func TestAptRepoManagedRemovePartialFailure(t *testing.T) {
	r := newAptRig(t)
	if err := os.WriteFile(filepath.Join(r.dir, "imas-uat-x.list"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A non-empty directory under the .sources name can't be removed.
	if err := os.MkdirAll(filepath.Join(r.dir, "imas-uat-x.sources", "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := repoStep("", true).Apply(context.Background())
	if err == nil || !res.Failed {
		t.Fatalf("expected failure: %+v", res)
	}
	if r.exists("imas-uat-x.list") || !res.Changed {
		t.Errorf("the .list was removed, so the result must report a change: %+v", res)
	}
}

func TestAptRepoManagedBadInput(t *testing.T) {
	r := newAptRig(t)
	for _, p := range []Pkg{
		repoStep("ppa:deadsnakes/ppa", false),
		repoStep("", false),
		{name: "a/b", method: "repo_managed", properties: map[string]interface{}{"name": "a/b", "absent": true}},
	} {
		res, err := p.Apply(context.Background())
		if err == nil || !res.Failed {
			t.Errorf("%v: expected failure, got %+v", p.properties, res)
		}
	}
	if r.updates != 0 {
		t.Error("bad input ran apt-get update")
	}
}
