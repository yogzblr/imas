//go:build uat

package uattests

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// write retries a recipe PUT or DELETE while the tenant's write budget
// (1/s, burst 10) answers 429.
func write(ctx context.Context, fn func() (*harness.Response, error)) (*harness.Response, error) {
	for i := 0; ; i++ {
		r, err := fn()
		if err != nil || r.Status != http.StatusTooManyRequests || i == 10 {
			return r, err
		}
		select {
		case <-ctx.Done():
			return r, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// put is PutRecipe through write.
func put(ctx context.Context, tok string, n int, name, content string, pre harness.Precondition) (harness.Recipe, *harness.Response, error) {
	var rec harness.Recipe
	r, err := write(ctx, func() (*harness.Response, error) {
		out, r, err := fleet.API.PutRecipe(ctx, tok, fleet.TenantID(n), name, content, pre)
		rec = out
		return r, err
	})
	return rec, r, err
}

// upload creates or replaces a recipe and deletes it when the test ends.
func upload(t *testing.T, sc *harness.Scenario, n int, name, content string) {
	t.Helper()
	tok := token(t, sc, n, harness.RoleAdmin)
	_, err := fleet.API.UploadRecipe(ctxFor(t, 2*time.Minute), tok, fleet.TenantID(n), name, content)
	sc.NoErr(err, "uploading recipe %s to tenant %d", name, n)
	t.Cleanup(func() { _, _ = fleet.API.DeleteRecipe(cleanupCtx(), tok, fleet.TenantID(n), name) })
}

// markerRecipe writes text to path with file.content.
func markerRecipe(step, path, text string) string {
	return fmt.Sprintf("steps:\n  %s:\n    file.content:\n      - name: '%s'\n      - text: %q\n",
		step, strings.ReplaceAll(path, "'", "''"), text)
}

func TestCoreR1_RecipeLifecycle(t *testing.T) {
	sc := harness.Begin(t, "R1")
	ctx := ctxFor(t, 10*time.Minute)
	tok := token(t, sc, 1, harness.RoleAdmin)
	tid := fleet.TenantID(1)
	name := "uat.r1." + harness.Nonce(8)
	v1 := markerRecipe("uat r1", "/var/tmp/imas-uat-r1", "one")
	v2 := markerRecipe("uat r1", "/var/tmp/imas-uat-r1", "two")
	t.Cleanup(func() { _, _ = fleet.API.DeleteRecipe(cleanupCtx(), tok, tid, name) })

	sc.Step("PUT without a precondition")
	_, r, err := put(ctx, tok, 1, name, v1, harness.Precondition{})
	sc.Check(r, err, http.StatusPreconditionRequired, "precondition_required", "PUT without If-Match or If-None-Match")

	sc.Step("create")
	rec, r, err := put(ctx, tok, 1, name, v1, harness.Create)
	sc.Expect(r, err, http.StatusCreated, "", "PUT If-None-Match: *")
	if rec.Name != name || !sha256Re.MatchString(rec.SHA256) || rec.Size != int64(len(v1)) {
		sc.Errorf("created %+v, want name %s, a sha256 and size %d", rec, name, len(v1))
	}
	if et := r.Header.Get("ETag"); et != `"`+rec.SHA256+`"` {
		sc.Errorf("ETag %q, want the quoted sha256", et)
	}
	sha1 := rec.SHA256

	sc.Step("create again")
	_, r, err = put(ctx, tok, 1, name, v1, harness.Create)
	sc.Check(r, err, http.StatusPreconditionFailed, "precondition_failed", "a second create")

	sc.Step("fetch")
	got, r, err := fleet.API.GetRecipe(ctx, tok, tid, name)
	sc.Expect(r, err, http.StatusOK, "", "GET")
	if got.Content == nil || *got.Content != v1 || got.SHA256 != sha1 {
		sc.Errorf("GET returned sha %s and different content", got.SHA256)
	}

	sc.Step("list")
	all, err := fleet.API.AllRecipes(ctx, tok, tid)
	sc.NoErr(err, "listing")
	found := false
	for _, x := range all {
		if x.Name == name {
			found = x.Size == int64(len(v1))
		}
	}
	if !found {
		sc.Errorf("the list lacks %s with size %d", name, len(v1))
	}

	sc.Step("replace that version")
	rec, r, err = put(ctx, tok, 1, name, v2, harness.ReplaceVersion(sha1))
	sc.Expect(r, err, http.StatusOK, "", "PUT If-Match: the current sha256")
	sha2 := rec.SHA256
	if sha2 == sha1 {
		sc.Errorf("the sha256 didn't change")
	}

	sc.Step("replace a stale version")
	_, r, err = put(ctx, tok, 1, name, v1, harness.ReplaceVersion(sha1))
	if sc.Check(r, err, http.StatusPreconditionFailed, "precondition_failed", "PUT If-Match: a stale sha256") {
		if cur, _ := r.Error.Details["current_sha256"].(string); cur != sha2 {
			sc.Errorf("details.current_sha256 %q, want %s", cur, sha2)
		}
	}

	sc.Step("refuse bad uploads")
	for _, c := range []struct {
		name, content, contentType string
		status                     int
		code                       string
	}{
		{"Bad.Name", v1, "", http.StatusBadRequest, "invalid_recipe_name"},
		{"tenants.x", v1, "", http.StatusBadRequest, "invalid_recipe_name"},
		{"uat.r1.init", v1, "", http.StatusBadRequest, "invalid_recipe_name"},
		{name + "x", "", "", http.StatusUnprocessableEntity, "recipe_empty"},
		{name + "x", "steps: {{ env \"HOME\" }}\n", "", http.StatusUnprocessableEntity, "recipe_template_forbidden"},
		{name + "x", "- a\n- b\n", "", http.StatusUnprocessableEntity, "recipe_yaml_invalid"},
		{name + "x", v1, "text/html", http.StatusUnsupportedMediaType, "unsupported_media_type"},
	} {
		r, err := write(ctx, func() (*harness.Response, error) {
			return fleet.API.Do(ctx, harness.Request{
				Method: http.MethodPut, Path: harness.TenantPath(tid, "recipes") + "/" + c.name, Token: tok,
				RawBody: []byte(c.content), ContentType: c.contentType, Header: http.Header{"If-None-Match": {"*"}},
			})
		})
		sc.Check(r, err, c.status, c.code, "PUT %s (%s)", c.name, c.code)
	}

	sc.Step("delete with a stale sha256")
	r, err = write(ctx, func() (*harness.Response, error) {
		return fleet.API.Do(ctx, harness.Request{Method: http.MethodDelete, Path: harness.TenantPath(tid, "recipes") + "/" + name, Token: tok,
			Header: http.Header{"If-Match": {`"` + sha1 + `"`}}})
	})
	sc.Check(r, err, http.StatusPreconditionFailed, "precondition_failed", "DELETE If-Match: a stale sha256")
	sc.Step("delete")
	r, err = write(ctx, func() (*harness.Response, error) { return fleet.API.DeleteRecipe(ctx, tok, tid, name) })
	sc.Check(r, err, http.StatusNoContent, "", "DELETE")
	sc.Step("it's gone")
	_, r, err = fleet.API.GetRecipe(ctx, tok, tid, name)
	sc.Check(r, err, http.StatusNotFound, "recipe_not_found", "GET after DELETE")
	r, err = write(ctx, func() (*harness.Response, error) { return fleet.API.DeleteRecipe(ctx, tok, tid, name) })
	sc.Check(r, err, http.StatusNotFound, "recipe_not_found", "a second DELETE")
}

func TestCoreR2_RecipeRoles(t *testing.T) {
	sc := harness.Begin(t, "R2")
	if !fleet.Tokens.HasUser(1, harness.RoleReadOnly) {
		sc.Skipf("keycloak.json has no read only user for tenant 1 (tenants.1.readonly)")
	}
	ctx := ctxFor(t, 5*time.Minute)
	tid := fleet.TenantID(1)
	ro := token(t, sc, 1, harness.RoleReadOnly)
	name := "uat.r2." + harness.Nonce(8)
	upload(t, sc, 1, name, markerRecipe("uat r2", "/var/tmp/imas-uat-r2", "r2"))

	sc.Step("the read only user reads")
	_, _, r, err := fleet.API.ListRecipes(ctx, ro, tid, 10, "")
	sc.Check(r, err, http.StatusOK, "", "list with the read role")
	_, r, err = fleet.API.GetRecipe(ctx, ro, tid, name)
	sc.Check(r, err, http.StatusOK, "", "GET with the read role")
	sc.Step("the read only user can't write")
	_, r, err = fleet.API.PutRecipe(ctx, ro, tid, name, "steps: {}\n", harness.Replace)
	sc.Check(r, err, http.StatusForbidden, "forbidden", "PUT with the read role only")
	_, r, err = fleet.API.PutRecipe(ctx, ro, tid, name+"x", "steps: {}\n", harness.Create)
	sc.Check(r, err, http.StatusForbidden, "forbidden", "creating with the read role only")
	r, err = fleet.API.DeleteRecipe(ctx, ro, tid, name)
	sc.Check(r, err, http.StatusForbidden, "forbidden", "DELETE with the read role only")
	sc.Step("the recipe is untouched")
	got, r, err := fleet.API.GetRecipe(ctx, token(t, sc, 1, harness.RoleAdmin), tid, name)
	sc.Expect(r, err, http.StatusOK, "", "GET as admin")
	if got.Content == nil || !strings.Contains(*got.Content, "r2") {
		sc.Errorf("the recipe changed")
	}
}

// osRecipe writes text to <temp>/<file> on every OS, choosing the path
// with an OS condition on the sprout's os fact.
func osRecipe(step, file, text string) string {
	return fmt.Sprintf(`steps:
  %s:
    file.content:
{{- if eq (props "os") "windows" }}
      - name: 'C:\Windows\Temp\%s'
{{- else }}
      - name: /var/tmp/%s
{{- end }}
      - text: %q
`, step, file, file, text)
}

func TestCoreR3_RecipesTenantScoped(t *testing.T) {
	sc := harness.Begin(t, "R3")
	f := ready(t, sc)
	ctx := ctxFor(t, 20*time.Minute)
	nonce := harness.Nonce(8)
	name := "uat.r3." + nonce
	file := "imas-uat-r3-" + nonce + ".txt"
	text := map[int]string{1: "tenant one " + nonce, 2: "tenant two " + nonce}
	for _, n := range []int{1, 2} {
		upload(t, sc, n, name, osRecipe("uat r3", file, text[n]))
	}
	for _, n := range []int{1, 2} {
		sc.Step("tenant %d reads its own %s", n, name)
		got, r, err := f.API.GetRecipe(ctx, token(t, sc, n, harness.RoleAdmin), f.TenantID(n), name)
		sc.Expect(r, err, http.StatusOK, "", "GET")
		if got.Content == nil || !strings.Contains(*got.Content, text[n]) {
			sc.Errorf("tenant %d read the other tenant's content", n)
		}
	}
	for _, osName := range []string{harness.OSUbuntu, harness.OSAlma, harness.OSWindows} {
		a := f.Sprouts(harness.InTenant(1), harness.WithOS(osName))
		b := f.Sprouts(harness.InTenant(2), harness.WithOS(osName))
		if len(a) == 0 || len(b) == 0 {
			continue
		}
		t.Run(osName, func(t *testing.T) {
			t.Parallel()
			osc := sc.ForSprout(t, harness.Sprout{OS: osName})
			for n, sp := range map[int]harness.Sprout{1: a[0], 2: b[0]} {
				osc.Step("tenant %d cooks %s on %s", n, name, sp.VM)
				bt, err := f.Cook(ctx, n, []harness.Sprout{sp}, name, false)
				osc.NoErr(err, "the cook")
				osc.ExpectItem(bt, sp, harness.ItemSucceeded, "")
				fi, err := f.File(ctx, sp, sp.TempPath(file))
				osc.NoErr(err, "reading the file on %s", sp.VM)
				if fi.Content != text[n]+"\n" {
					osc.Errorf("%s holds %q, want tenant %d's %q: the cook didn't use its own tenant's recipe", sp.VM, fi.Content, n, text[n])
				}
			}
		})
	}
}

// familyRecipes uploads one recipe per family to tenant n, writing text
// to file in the family's temp directory, and returns their names.
func familyRecipes(t *testing.T, sc *harness.Scenario, n int, id, file, text string) map[string]string {
	t.Helper()
	nonce := harness.Nonce(8)
	names := map[string]string{
		harness.FamilyLinux:   "uat." + id + "." + nonce + ".linux",
		harness.FamilyWindows: "uat." + id + "." + nonce + ".windows",
	}
	upload(t, sc, n, names[harness.FamilyLinux], markerRecipe("uat "+id, "/var/tmp/"+file, text))
	upload(t, sc, n, names[harness.FamilyWindows], markerRecipe("uat "+id, `C:\Windows\Temp\`+file, text))
	return names
}

func TestCoreR4_CookByName(t *testing.T) {
	sc := harness.Begin(t, "R4")
	f := ready(t, sc)
	nonce := harness.Nonce(8)
	file := "imas-uat-r4-" + nonce + ".txt"
	text := "r4 " + nonce
	names := familyRecipes(t, sc, 1, "r4", file, text)
	f.EachSprout(t, sc, f.Sprouts(harness.InTenant(1)), func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
		ctx := ctxFor(t, 15*time.Minute)
		recipe := names[sp.Family()]
		sc.Step("cook %s", recipe)
		b, err := f.Cook(ctx, 1, []harness.Sprout{sp}, recipe, false)
		sc.NoErr(err, "the cook")
		it := sc.ExpectItem(b, sp, harness.ItemSucceeded, "")
		if it.JID == "" {
			sc.Errorf("the cook item has no jid")
		}
		sc.Step("check the file on the host")
		fi, err := f.File(ctx, sp, sp.TempPath(file))
		sc.NoErr(err, "reading the file")
		if !fi.Exists || fi.Content != text+"\n" {
			sc.Errorf("%s: exists %v, content %q, want %q", sp.TempPath(file), fi.Exists, fi.Content, text+"\n")
		}
	})
}

func TestCoreR5_CookTestMode(t *testing.T) {
	sc := harness.Begin(t, "R5")
	f := ready(t, sc)
	nonce := harness.Nonce(8)
	file := "imas-uat-r5-" + nonce + ".txt"
	text := "r5 " + nonce
	names := familyRecipes(t, sc, 1, "r5", file, text)
	// What the API can't show: a batch item carries status, jid and an
	// error code, not a cook's per-step "changed" results, so "reports
	// pending changes" is asserted by its effect instead: test mode
	// succeeds and leaves the host untouched, a real cook makes the change,
	// and test mode afterwards still changes nothing.
	f.EachSprout(t, sc, f.Sprouts(harness.InTenant(1)), func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
		ctx := ctxFor(t, 20*time.Minute)
		recipe, path := names[sp.Family()], sp.TempPath(file)
		cook := func(test bool) {
			b, err := f.Cook(ctx, 1, []harness.Sprout{sp}, recipe, test)
			sc.NoErr(err, "the cook (test=%v)", test)
			sc.ExpectItem(b, sp, harness.ItemSucceeded, "")
		}
		sc.Step("cook in test mode")
		cook(true)
		fi, err := f.File(ctx, sp, path)
		sc.NoErr(err, "reading the file")
		if fi.Exists {
			sc.Fatalf("test mode created %s", path)
		}
		sc.Step("cook for real")
		cook(false)
		fi, err = f.File(ctx, sp, path)
		sc.NoErr(err, "reading the file")
		if !fi.Exists || fi.Content != text+"\n" {
			sc.Fatalf("the real cook left %s exists=%v content %q", path, fi.Exists, fi.Content)
		}
		sc.Step("cook in test mode again, then for real again")
		time.Sleep(2 * time.Second) // a rewrite would move the mtime
		cook(true)
		cook(false)
		after, err := f.File(ctx, sp, path)
		sc.NoErr(err, "reading the file")
		if after.MTime != fi.MTime || after.Content != fi.Content {
			sc.Errorf("the file changed after the change was already made (mtime %d -> %d): not idempotent", fi.MTime, after.MTime)
		}
	})
}

func TestCoreR6_TemplatesOverMixedOS(t *testing.T) {
	sc := harness.Begin(t, "R6")
	f := ready(t, sc)
	nonce := harness.Nonce(8)
	name := "uat.r6." + nonce
	file := "imas-uat-r6-" + nonce + ".txt"
	recipe := fmt.Sprintf(`steps:
  uat r6 marker:
    file.content:
{{- if eq (props "os") "windows" }}
      - name: 'C:\Windows\Temp\%[1]s'
{{- else }}
      - name: /var/tmp/%[1]s
{{- end }}
      - text: "r6 os={{ props "os" }} sprout={{ sproutID }} upper={{ upper (sproutID) }} named={{ if hostname }}yes{{ else }}no{{ end }} %[2]s"
`, file, nonce)
	upload(t, sc, 1, name, recipe)
	sprouts := f.Sprouts(harness.InTenant(1))
	sc.Step("cook %s over every sprout of tenant 1 in one batch", name)
	b, batchErr := f.Cook(ctxFor(t, 15*time.Minute), 1, sprouts, name, false)
	f.EachSprout(t, sc, sprouts, func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
		ctx := ctxFor(t, 10*time.Minute)
		sc.NoErr(batchErr, "the batch")
		sc.ExpectItem(b, sp, harness.ItemSucceeded, "")
		goos := "linux"
		if sp.IsWindows() {
			goos = "windows"
		}
		want := fmt.Sprintf("r6 os=%s sprout=%s upper=%s named=yes %s\n", goos, sp.SproutID, strings.ToUpper(sp.SproutID), nonce)
		sc.Step("check the rendered file")
		fi, err := f.File(ctx, sp, sp.TempPath(file))
		sc.NoErr(err, "reading the file")
		if fi.Content != want {
			sc.Errorf("content %q, want %q", fi.Content, want)
		}
	})
}
