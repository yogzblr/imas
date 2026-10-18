package packagingtest

// Tests for the release scripts BUILD-STATUS P10 added (unit V2):
// packaging/release/cosign-identity.sh (the pinned keyless signer
// identity), packaging/release/check-release-tag.sh (a moved tag cannot
// rebuild its release) and packaging/helm/ghcr-chart.sh (a published chart
// is pullable anonymously and linked to the repository). gh and GHCR are
// fakes: a gh script on PATH and an httptest server.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRoot is the repository root: go test runs in packaging/test.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// runScript runs a repo script with bash and returns its combined output
// and exit code. env replaces the proxy settings so curl reaches the
// httptest server directly.
func runScript(t *testing.T, env []string, script string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{filepath.Join(repoRoot(t), script)}, args...)...)
	base := []string{}
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(k) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "GHCR_USER", "GHCR_TOKEN":
			continue
		}
		base = append(base, kv)
	}
	cmd.Env = append(base, env...)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exit):
		return string(out), exit.ExitCode()
	default:
		t.Fatalf("run %s: %v", script, err)
		return "", -1
	}
}

func TestCosignIdentity(t *testing.T) {
	const script = "packaging/release/cosign-identity.sh"
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"release.yml", "v0.1.0"}, "https://github.com/yogzblr/imas/.github/workflows/release.yml@refs/tags/v0.1.0"},
		{[]string{"release.yml", "v0.1.0-rc.14"}, "https://github.com/yogzblr/imas/.github/workflows/release.yml@refs/tags/v0.1.0-rc.14"},
		{[]string{"publish-packages.yml", "v1.20.3"}, "https://github.com/yogzblr/imas/.github/workflows/publish-packages.yml@refs/tags/v1.20.3"},
		{[]string{"publish-packages.yml", "v0.1.0-beta.2"}, "https://github.com/yogzblr/imas/.github/workflows/publish-packages.yml@refs/tags/v0.1.0-beta.2"},
		{[]string{"--issuer"}, "https://token.actions.githubusercontent.com"},
	} {
		out, code := runScript(t, nil, script, tc.args...)
		if code != 0 || out != tc.want+"\n" {
			t.Errorf("%v: got %q (exit %d), want %q", tc.args, out, code, tc.want)
		}
	}
	for _, args := range [][]string{
		{},
		{"release.yml"},
		{"snapshot.yml", "v0.1.0"},
		{"release.yml", "0.1.0"},         // no v
		{"release.yml", "v0.1"},          // not X.Y.Z
		{"release.yml", "v01.0.0"},       // leading zero
		{"release.yml", "v0.1.0+git"},    // build metadata
		{"release.yml", "v0.1.0-rc.*"},   // a pattern
		{"release.yml", "v0.1.0 v0.2.0"}, // two
		{"release.yml", "main"},          // a branch
		{"publish-packages.yml", "v[0-9].*"},
	} {
		out, code := runScript(t, nil, script, args...)
		if code != 2 || !strings.Contains(out, "cosign-identity.sh:") {
			t.Errorf("%q: got %q (exit %d), want a refusal (exit 2)", args, out, code)
		}
	}
}

// Every cosign verify of a release pins the exact identity from
// cosign-identity.sh: no regular expression is left in the workflows or
// the docs that tell users how to verify.
func TestCosignIdentityIsPinnedEverywhere(t *testing.T) {
	root := repoRoot(t)
	for _, f := range []string{
		".github/workflows/publish-packages.yml",
		".github/workflows/release.yml",
		"docs/RELEASING.md",
		"SECURITY.md",
		"uat/README.md",
		"ansible/README.md",
	} {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if strings.Contains(s, "certificate-identity-regexp") {
			t.Errorf("%s: uses --certificate-identity-regexp; pass --certificate-identity from packaging/release/cosign-identity.sh", f)
		}
		if regexp.MustCompile(`workflows/[a-z-]+\\?\.yml@(\.\+|refs/tags/v\[)`).MatchString(s) {
			t.Errorf("%s: still names a signer identity pattern", f)
		}
	}
	b, err := os.ReadFile(filepath.Join(root, ".github/workflows/publish-packages.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := string(b)
	for _, want := range []string{
		"packaging/release/cosign-identity.sh release.yml",
		"packaging/release/cosign-identity.sh publish-packages.yml",
		"packaging/helm/ghcr-chart.sh check",
		"packaging/helm/ghcr-chart.sh digest",
	} {
		if !strings.Contains(wf, want) {
			t.Errorf("publish-packages.yml does not run %q", want)
		}
	}
	if n := strings.Count(wf, "--certificate-identity \""); n < 3 {
		t.Errorf("publish-packages.yml: %d pinned --certificate-identity flags, want one per cosign verify (checksums, images, charts)", n)
	}
}

// release.yml checks for a moved tag before GoReleaser can touch the
// release, and every release records the commit it was built from.
func TestReleaseChecksTheTagFirst(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, ".github/workflows/release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	wf := string(b)
	check := strings.Index(wf, "packaging/release/check-release-tag.sh")
	gr := strings.Index(wf, "goreleaser/goreleaser-action")
	if check < 0 || gr < 0 || check > gr {
		t.Errorf("release.yml must run packaging/release/check-release-tag.sh before GoReleaser (at %d, GoReleaser at %d)", check, gr)
	}
	g, err := os.ReadFile(filepath.Join(root, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(g), `target_commitish: "{{ .FullCommit }}"`) {
		t.Error(`.goreleaser.yaml: release.target_commitish must be "{{ .FullCommit }}", which check-release-tag.sh compares`)
	}
	// Owner decision V2: the release notes say how to verify the charts
	// and how to do the owner step the workflow's token cannot.
	for _, want := range []string{
		"publish-packages.yml@refs/tags/{{ .Tag }}",
		"release.yml@refs/tags/{{ .Tag }}",
		"Change visibility to **Public**",
		"Connect repository `yogzblr/imas`",
	} {
		if !strings.Contains(string(g), want) {
			t.Errorf(".goreleaser.yaml release.footer does not say %q", want)
		}
	}
}

func TestCheckReleaseTag(t *testing.T) {
	const (
		script = "packaging/release/check-release-tag.sh"
		built  = "1111111111111111111111111111111111111111"
		moved  = "2222222222222222222222222222222222222222"
	)
	release := func(tag, target string, draft bool, assets int) map[string]any {
		a := make([]map[string]any, assets)
		for i := range a {
			a[i] = map[string]any{"name": fmt.Sprintf("asset-%d", i)}
		}
		return map[string]any{"tag_name": tag, "target_commitish": target, "draft": draft, "assets": a,
			"html_url": "https://github.com/yogzblr/imas/releases/tag/" + tag}
	}
	for _, tc := range []struct {
		name  string
		pages [][]map[string]any // what gh api --paginate prints, one array per page
		fail  bool
		want  string
	}{
		{"no releases", [][]map[string]any{{}}, false, "no release for v0.1.0-rc.14 yet"},
		{"other tags only", [][]map[string]any{{release("v0.1.0-rc.13", built, false, 47)}}, false, "no release for"},
		{"re-run on the same commit", [][]map[string]any{{release("v0.1.0-rc.14", built, true, 3)}}, false, "a re-run, allowed"},
		{"published, tag moved", [][]map[string]any{{release("v0.1.0-rc.14", moved, false, 47)}}, true, "a tag never moves"},
		{"draft, tag moved", [][]map[string]any{{release("v0.1.0-rc.14", moved, true, 47)}}, true, "built from " + moved},
		{"moved, on the second page", [][]map[string]any{{release("v0.1.0-rc.13", built, false, 47)}, {release("v0.1.0-rc.14", moved, false, 47)}}, true, "a tag never moves"},
		{"made in the UI, not built", [][]map[string]any{{release("v0.1.0-rc.14", "main", false, 0)}}, false, "not built before, allowed"},
		{"built with no recorded commit", [][]map[string]any{{release("v0.1.0-rc.14", "main", false, 47)}}, true, "cannot be checked"},
		{"empty target, built", [][]map[string]any{{release("v0.1.0-rc.14", "", true, 2)}}, true, "cannot be checked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			var out strings.Builder
			for _, p := range tc.pages {
				b, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				out.Write(b)
				out.WriteByte('\n')
			}
			if err := os.WriteFile(filepath.Join(dir, "releases.json"), []byte(out.String()), 0o644); err != nil {
				t.Fatal(err)
			}
			// The fake gh answers only the call the script must make.
			gh := `#!/usr/bin/env bash
[ "$*" = "api --paginate repos/yogzblr/imas/releases?per_page=100" ] || { echo "unexpected gh $*" >&2; exit 9; }
cat "` + filepath.Join(dir, "releases.json") + `"
`
			if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(gh), 0o755); err != nil {
				t.Fatal(err)
			}
			got, code := runScript(t, []string{"PATH=" + dir + ":" + os.Getenv("PATH")}, script, "yogzblr/imas", "v0.1.0-rc.14", built)
			if (code != 0) != tc.fail || !strings.Contains(got, tc.want) {
				t.Errorf("got %q (exit %d), want fail=%v and %q", got, code, tc.fail, tc.want)
			}
			if tc.fail && !strings.Contains(got, "::error::") {
				t.Errorf("a refusal must be a workflow error: %q", got)
			}
		})
	}
	if got, code := runScript(t, nil, script, "yogzblr/imas", "v0.1.0", "abc"); code != 1 || !strings.Contains(got, "not a full commit SHA") {
		t.Errorf("short SHA: got %q (exit %d)", got, code)
	}
}

// fakeGHCR is the part of GHCR's distribution API and GitHub's package
// page ghcr-chart.sh uses.
type fakeGHCR struct {
	private    bool   // anonymous token requests are DENIED
	linked     bool   // the repository package page exists
	source     string // org.opencontainers.image.source
	versions   map[string]bool
	manifest   []byte
	layer      []byte
	sawBasic   bool
	sawPackage string
}

func (f *fakeGHCR) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.EscapedPath()
		switch {
		case path == "/token":
			if r.URL.Query().Get("scope") != "repository:yogzblr/charts/farmer:pull" {
				http.Error(w, `{"errors":[{"code":"DENIED"}]}`, http.StatusForbidden)
				return
			}
			_, _, basic := r.BasicAuth()
			f.sawBasic = f.sawBasic || basic
			if f.private && !basic {
				http.Error(w, `{"errors":[{"code":"DENIED"}]}`, http.StatusForbidden)
				return
			}
			fmt.Fprint(w, `{"token":"t0k"}`)
		case strings.HasPrefix(path, "/v2/yogzblr/charts/farmer/manifests/"):
			if r.Header.Get("Authorization") != "Bearer t0k" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if !f.versions[strings.TrimPrefix(path, "/v2/yogzblr/charts/farmer/manifests/")] {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Write(f.manifest)
		case path == "/v2/yogzblr/charts/farmer/blobs/"+digestOf(f.layer):
			// GHCR redirects a blob to its storage host.
			http.Redirect(w, r, "/storage/layer", http.StatusTemporaryRedirect)
		case path == "/storage/layer":
			w.Write(f.layer)
		case strings.HasPrefix(path, "/yogzblr/imas/pkgs/container/"):
			f.sawPackage = strings.TrimPrefix(path, "/yogzblr/imas/pkgs/container/")
			if !f.linked || f.sawPackage != "charts%2Ffarmer" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			fmt.Fprint(w, "<title>Package charts/farmer · GitHub</title>")
		default:
			t.Logf("fake GHCR: unexpected %s", path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func newFakeGHCR(t *testing.T) *fakeGHCR {
	f := &fakeGHCR{linked: true, source: "https://github.com/yogzblr/imas", versions: map[string]bool{"0.1.0-rc.14": true}}
	f.layer = []byte("\x1f\x8b fake chart")
	f.build(t)
	return f
}

func (f *fakeGHCR) build(t *testing.T) {
	m := map[string]any{
		"schemaVersion": 2,
		"config":        map[string]any{"mediaType": "application/vnd.cncf.helm.config.v1+json", "digest": digestOf([]byte("{}")), "size": 2},
		"layers": []any{map[string]any{
			"mediaType": "application/vnd.cncf.helm.chart.content.v1.tar+gzip", "digest": digestOf(f.layer), "size": len(f.layer)}},
		"annotations": map[string]string{"org.opencontainers.image.source": f.source, "org.opencontainers.image.version": "0.1.0-rc.14"},
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	f.manifest = b
}

func TestGHCRChart(t *testing.T) {
	const script = "packaging/helm/ghcr-chart.sh"
	run := func(t *testing.T, f *fakeGHCR, extra []string, args ...string) (string, int) {
		srv := httptest.NewServer(f.handler(t))
		t.Cleanup(srv.Close)
		env := append([]string{"IMAS_GHCR_URL=" + srv.URL, "IMAS_GITHUB_URL=" + srv.URL}, extra...)
		return runScript(t, env, script, args...)
	}

	t.Run("public and linked", func(t *testing.T) {
		f := newFakeGHCR(t)
		got, code := run(t, f, nil, "check", "farmer", "0.1.0-rc.14", digestOf(f.manifest))
		if code != 0 || !strings.Contains(got, "pulled oci://") || !strings.Contains(got, "public and linked to yogzblr/imas") {
			t.Fatalf("got %q (exit %d)", got, code)
		}
		if f.sawPackage != "charts%2Ffarmer" {
			t.Errorf("package page asked for %q, want charts%%2Ffarmer", f.sawPackage)
		}
	})
	t.Run("check ignores the run's credential", func(t *testing.T) {
		f := newFakeGHCR(t)
		f.private = true
		got, code := run(t, f, []string{"GHCR_USER=bot", "GHCR_TOKEN=secret"}, "check", "farmer", "0.1.0-rc.14", digestOf(f.manifest))
		if code != 1 || f.sawBasic {
			t.Fatalf("a private package passed the anonymous check with the run's credential: %q (exit %d, basic auth %v)", got, code, f.sawBasic)
		}
	})
	for _, tc := range []struct {
		name   string
		setup  func(*fakeGHCR)
		digest func(*fakeGHCR) string
		want   []string
	}{
		{"private", func(f *fakeGHCR) { f.private = true }, nil,
			[]string{"cannot be pulled anonymously", "Change visibility, Public", "/users/yogzblr/packages/container/charts%2Ffarmer/settings"}},
		{"not linked", func(f *fakeGHCR) { f.linked = false }, nil,
			[]string{"is not linked to yogzblr/imas", "Connect repository", "Manage Actions access"}},
		{"source annotation wrong", func(f *fakeGHCR) { f.source = "https://github.com/someone/else" }, nil,
			[]string{"names source 'https://github.com/someone/else'", "sources[0]"}},
		{"digest moved", nil, func(*fakeGHCR) string { return digestOf([]byte("another push")) },
			[]string{"not the pushed and signed", "never re-push"}},
		{"version missing", func(f *fakeGHCR) { f.versions = map[string]bool{} }, nil,
			[]string{"cannot be pulled anonymously (HTTP 404"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeGHCR(t)
			if tc.setup != nil {
				tc.setup(f)
				f.build(t)
			}
			d := digestOf(f.manifest)
			if tc.digest != nil {
				d = tc.digest(f)
			}
			got, code := run(t, f, nil, "check", "farmer", "0.1.0-rc.14", d)
			if code != 1 || !strings.Contains(got, "::error::") {
				t.Fatalf("got %q (exit %d), want a workflow error", got, code)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("message %q does not say %q", got, w)
				}
			}
		})
	}

	t.Run("digest", func(t *testing.T) {
		f := newFakeGHCR(t)
		got, code := run(t, f, nil, "digest", "farmer", "0.1.0-rc.14")
		if code != 0 || got != digestOf(f.manifest)+"\n" {
			t.Fatalf("got %q (exit %d), want %s", got, code, digestOf(f.manifest))
		}
		if got, code := run(t, f, nil, "digest", "farmer", "0.1.0-rc.15"); code != 3 {
			t.Errorf("absent version: got %q (exit %d), want exit 3", got, code)
		}
	})
	t.Run("digest of a private package uses the run's credential", func(t *testing.T) {
		f := newFakeGHCR(t)
		f.private = true
		got, code := run(t, f, []string{"GHCR_USER=bot", "GHCR_TOKEN=secret"}, "digest", "farmer", "0.1.0-rc.14")
		if code != 0 || !f.sawBasic || got != digestOf(f.manifest)+"\n" {
			t.Fatalf("got %q (exit %d, basic auth %v)", got, code, f.sawBasic)
		}
		if got, code := run(t, f, nil, "digest", "farmer", "0.1.0-rc.14"); code != 3 {
			t.Errorf("anonymous, private: got %q (exit %d), want exit 3 (not visible)", got, code)
		}
	})
	t.Run("usage", func(t *testing.T) {
		f := newFakeGHCR(t)
		for _, args := range [][]string{{}, {"push", "farmer", "1.0.0"}, {"check", "farmer", "1.0.0"}, {"digest", "farmer"}} {
			if got, code := run(t, f, nil, args...); code != 2 {
				t.Errorf("%q: got %q (exit %d), want usage (exit 2)", args, got, code)
			}
		}
		for _, args := range [][]string{{"digest", "../x", "1.0.0"}, {"digest", "farmer", "1.0.0/../x"}, {"check", "farmer", "1.0.0", "sha256:abc"}} {
			if got, code := run(t, f, nil, args...); code != 1 {
				t.Errorf("%q: got %q (exit %d), want a refusal (exit 1)", args, got, code)
			}
		}
	})
}
