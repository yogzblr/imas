package saasapi

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The example object-store policy for saasapi's recipe credential
// (deploy/helm/farmer/files/objectstore-policies/saasapi-recipes.json)
// must allow exactly what the recipe routes do, and nothing on sprouts/,
// jobs/ or the platform prefix. IAM's '*' matches across '/', so this also
// pins that the audit prefix is outside every pattern that grants
// GetObject or DeleteObject (saasapi can't erase its own audit trail).

type iamStatement struct {
	Sid       string
	Action    []string
	Resource  []string
	Condition map[string]map[string][]string
}

func loadRecipePolicy(t *testing.T) []iamStatement {
	t.Helper()
	b, err := os.ReadFile("../../deploy/helm/farmer/files/objectstore-policies/saasapi-recipes.json")
	if err != nil {
		t.Fatal(err)
	}
	var p struct{ Statement []iamStatement }
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	return p.Statement
}

// iamMatch reports whether s matches the IAM wildcard pattern (where '*'
// is any run of characters, '/' included, and '?' any one character).
func iamMatch(pattern, s string) bool {
	re := "^" + strings.NewReplacer(`\*`, ".*", `\?`, ".").Replace(regexp.QuoteMeta(pattern)) + "$"
	return regexp.MustCompile(re).MatchString(s)
}

// allowed reports whether the policy allows action on the object key.
func allowed(stmts []iamStatement, action, key string) bool {
	for _, s := range stmts {
		if !slices.Contains(s.Action, action) {
			continue
		}
		for _, r := range s.Resource {
			if iamMatch(r, "arn:aws:s3:::RECIPE_BUCKET/"+key) {
				return true
			}
		}
	}
	return false
}

func TestRecipeObjectStorePolicy(t *testing.T) {
	stmts := loadRecipePolicy(t)
	recipeKey, err := recipeObjectKey("t_a", "web.nginx")
	if err != nil {
		t.Fatal(err)
	}
	auditKey, err := recipeAuditKey("t_a", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"} {
		if !allowed(stmts, a, recipeKey) {
			t.Errorf("%s denied on a recipe key %s", a, recipeKey)
		}
	}
	if !allowed(stmts, "s3:PutObject", auditKey) {
		t.Errorf("PutObject denied on an audit key %s", auditKey)
	}
	for _, a := range []string{"s3:GetObject", "s3:DeleteObject"} {
		if allowed(stmts, a, auditKey) {
			t.Errorf("%s allowed on an audit key %s: saasapi could erase its audit trail", a, auditKey)
		}
	}
	for _, key := range []string{
		"sprouts/t_a/web-01/recipe.json", "jobs/t_a/x.log", "recipes/web/nginx.imas", "platform/web.imas",
		"srv/imas/recipes/prod/web.imas", "tenantsx/t_a/recipes/web.imas", "other/tenants/t_a/recipes/x.imas",
	} {
		for _, a := range []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"} {
			if allowed(stmts, a, key) {
				t.Errorf("%s allowed on %s", a, key)
			}
		}
	}
	// Listing is limited to the tenant recipe prefixes saasapi lists.
	for _, s := range stmts {
		if !slices.Contains(s.Action, "s3:ListBucket") {
			continue
		}
		prefixes := s.Condition["StringLike"]["s3:prefix"]
		if len(prefixes) == 0 {
			t.Fatal("ListBucket without a prefix condition")
		}
		match := func(p string) bool {
			return slices.ContainsFunc(prefixes, func(pat string) bool { return iamMatch(pat, p) })
		}
		if !match("tenants/t_a/recipes/") {
			t.Error("listing a tenant's recipes is denied")
		}
		for _, p := range []string{"", "sprouts/", "tenants/", "recipes/", "jobs/"} {
			if match(p) {
				t.Errorf("listing %q allowed", p)
			}
		}
	}
}
