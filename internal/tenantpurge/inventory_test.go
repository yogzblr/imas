package tenantpurge_test

// S6 decision 2: every table with a tenant_id column, every object key
// root and every Valkey key prefix in the code is either purged or kept
// for a stated reason. Add one without deciding which, and this fails
// and says so.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm/schema"

	"github.com/yogzblr/imas/internal/lease"
	"github.com/yogzblr/imas/internal/migrations"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pxc"
	"github.com/yogzblr/imas/internal/saasapi"
	"github.com/yogzblr/imas/internal/tenantpurge"
)

const decide = "add it to tenantpurge's purge lists (FarmerTables, SaasTables, PurgeRoots, PurgeValkeyPrefixes) or keep lists (KeepTables, KeepRoots, KeepValkeyPrefixes) with the reason it stays (docs/briefs/S6-tenant-erasure.md, decision 2)"

// decided reports whether schema.table is purged or kept.
func decided(schemaName, table string) bool {
	list := tenantpurge.FarmerTables
	if schemaName == "saas" {
		list = tenantpurge.SaasTables
	}
	_, kept := tenantpurge.KeepTables[schemaName+"."+table]
	return slices.Contains(list, table) || kept
}

var (
	createTable = regexp.MustCompile("(?is)CREATE TABLE(?: IF NOT EXISTS)?\\s+`?([a-z0-9_]+)`?\\s*\\((.*?)\\)\\s*ENGINE")
	addTenantID = regexp.MustCompile("(?i)ALTER TABLE\\s+`?([a-z0-9_]+)`?\\s+ADD COLUMN\\s+`?tenant_id`?")
)

// migrationTenantTables returns the tables a migration set creates with,
// or adds, a tenant_id column.
func migrationTenantTables(t *testing.T, set migrations.Set) []string {
	t.Helper()
	var tables []string
	err := fs.WalkDir(set.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return err
		}
		b, err := fs.ReadFile(set.FS(), path)
		if err != nil {
			return err
		}
		for _, m := range createTable.FindAllStringSubmatch(string(b), -1) {
			if regexp.MustCompile("(?m)^\\s*`?tenant_id`?\\s").MatchString(m[2]) {
				tables = append(tables, m[1])
			}
		}
		for _, m := range addTenantID.FindAllStringSubmatch(string(b), -1) {
			tables = append(tables, m[1])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tables
}

func TestInventoryCoversMigrations(t *testing.T) {
	for _, c := range []struct {
		name string
		set  migrations.Set
	}{{"farmer", migrations.Farmer}, {"saas", migrations.Saas}} {
		tables := migrationTenantTables(t, c.set)
		if len(tables) == 0 {
			t.Fatalf("no %s table with tenant_id found: the migration parser is broken", c.name)
		}
		for _, table := range tables {
			if !decided(c.name, table) {
				t.Errorf("%s.%s has a tenant_id column and is neither purged nor kept: %s", c.name, table, decide)
			}
		}
	}
	// The lists name only real tables of their own schema.
	farmerAll, saasAll := allMigrationTables(t, migrations.Farmer), allMigrationTables(t, migrations.Saas)
	for _, table := range tenantpurge.FarmerTables {
		if !slices.Contains(migrationTenantTables(t, migrations.Farmer), table) {
			t.Errorf("FarmerTables lists %s, which no farmer migration creates with tenant_id", table)
		}
	}
	for _, table := range tenantpurge.SaasTables {
		if !slices.Contains(migrationTenantTables(t, migrations.Saas), table) {
			t.Errorf("SaasTables lists %s, which no saas migration creates with tenant_id", table)
		}
	}
	for key := range tenantpurge.KeepTables {
		s, table, _ := strings.Cut(key, ".")
		if (s == "farmer" && !slices.Contains(farmerAll, table)) || (s == "saas" && !slices.Contains(saasAll, table)) || (s != "farmer" && s != "saas") {
			t.Errorf("KeepTables lists %s, which no migration creates", key)
		}
	}
	// A tenant's own registry rows, keyed by id, are the tombstone.
	for _, key := range []string{"saas.tenants", "farmer.pki_tenants"} {
		if _, ok := tenantpurge.KeepTables[key]; !ok {
			t.Errorf("%s is the tombstone and must be in KeepTables", key)
		}
	}
}

var anyTable = regexp.MustCompile("(?i)CREATE TABLE(?: IF NOT EXISTS)?\\s+`?([a-z0-9_]+)`?")

func allMigrationTables(t *testing.T, set migrations.Set) []string {
	t.Helper()
	var tables []string
	_ = fs.WalkDir(set.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return err
		}
		b, _ := fs.ReadFile(set.FS(), path)
		for _, m := range anyTable.FindAllStringSubmatch(string(b), -1) {
			tables = append(tables, m[1])
		}
		return nil
	})
	return tables
}

func TestInventoryCoversModels(t *testing.T) {
	cache := &sync.Map{}
	check := func(schemaName string, models []any) {
		for _, m := range models {
			s, err := schema.Parse(m, cache, schema.NamingStrategy{})
			if err != nil {
				t.Fatalf("parsing %T: %v", m, err)
			}
			if s.LookUpField("tenant_id") != nil && !decided(schemaName, s.Table) {
				t.Errorf("model %T (%s.%s) has a tenant_id column and is neither purged nor kept: %s", m, schemaName, s.Table, decide)
			}
		}
	}
	check("farmer", append(append(pxc.Models(), pki.SproutJWTModels()...), &lease.JobLease{}))
	check("saas", append(saasapi.Models(), pki.SaaSAPICredentialStateModels()...))
}

// goFiles returns every non-test Go file under internal/ and cmd/.
func goFiles(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..")
	var files []string
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == "testdata" || strings.HasSuffix(d.Name(), "test") && path != filepath.Join(root, dir)) {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return files
}

// literalsOf returns the string literals, import paths aside, of a file
// that imports any of the import paths, or is this package's own.
func literalsOf(t *testing.T, path string, imports ...string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	found := filepath.Base(filepath.Dir(path)) == "tenantpurge"
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		if slices.Contains(imports, p) {
			found = true
		}
	}
	if !found {
		return nil
	}
	var lits []string
	ast.Inspect(f, func(n ast.Node) bool {
		if _, ok := n.(*ast.ImportSpec); ok {
			return false
		}
		if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			if s, err := strconv.Unquote(bl.Value); err == nil {
				lits = append(lits, s)
			}
		}
		return true
	})
	return lits
}

// objectRoot is a string literal that starts with an object key root:
// one lower-case segment and a slash, and is a prefix ("jobs/") or a key
// or format with more below it ("tenants/%s/recipe-audit/..."), not a
// media type ("application/json").
var objectRoot = regexp.MustCompile(`^([a-z][a-z0-9_-]*/)(?:$|.*[/%])`)

// notObjectRoots are literals of object store code that look like a key
// root and are something else.
var notObjectRoots = map[string]string{
	"imas-saasapi-credential-check/": "saasapi's startup credential probe keys, under the recipe bucket's roots and deleted at once",
	"events/":                        "a job's events directory, below jobs/<tenant_id>/<sprout_id>/<jid>/, never a root",
}

func TestInventoryCoversObjectRoots(t *testing.T) {
	purged := map[string]bool{}
	for _, roots := range tenantpurge.PurgeRoots {
		for _, r := range roots {
			purged[r] = true
		}
	}
	seen := map[string]bool{}
	for _, path := range goFiles(t) {
		for _, lit := range literalsOf(t, path, "github.com/yogzblr/imas/internal/objectstore", "github.com/yogzblr/imas/internal/tenantpurge") {
			m := objectRoot.FindStringSubmatch(lit)
			if m == nil || strings.Contains(lit, "://") {
				continue
			}
			root := m[1]
			seen[root] = true
			if _, kept := tenantpurge.KeepRoots[root]; !purged[root] && !kept && notObjectRoots[root] == "" {
				t.Errorf("%s: object key root %q is neither purged nor kept: %s", path, root, decide)
			}
		}
	}
	for _, root := range []string{tenantpurge.RootTenants, tenantpurge.RootSprouts, tenantpurge.RootJobs, "accounts/"} {
		if !seen[root] {
			t.Errorf("object root %q not found in the code: the scan is broken", root)
		}
	}
}

var valkeyPrefix = regexp.MustCompile(`^imas:[a-z_:]+$`)

func TestInventoryCoversValkeyPrefixes(t *testing.T) {
	seen := 0
	for _, path := range goFiles(t) {
		for _, lit := range literalsOf(t, path, "github.com/valkey-io/valkey-go", "github.com/yogzblr/imas/internal/tenantpurge") {
			if !valkeyPrefix.MatchString(lit) {
				continue
			}
			seen++
			ok := false
			for _, p := range tenantpurge.PurgeValkeyPrefixes {
				ok = ok || strings.HasPrefix(lit, p)
			}
			for p := range tenantpurge.KeepValkeyPrefixes {
				ok = ok || strings.HasPrefix(lit, p)
			}
			if !ok {
				t.Errorf("%s: Valkey key prefix %q is neither purged nor kept: %s", path, lit, decide)
			}
		}
	}
	if seen < 4 {
		t.Errorf("found %d Valkey key prefixes: the scan is broken", seen)
	}
}

// kvUsers are the Go files that read or write OpenBao KV v2 (a "/data/"
// path, or the internal/openbaokv client), each with what it holds and
// whether a purge erases it. TestInventoryKV fails on a KV user missing
// here: a new one may hold a tenant's material.
var kvUsers = map[string]string{
	"internal/pki/tenantbox.go":                    "purged: one payload-encryption keypair per tenant (KVPaths)",
	"internal/pki/tenantpurge.go":                  "purged: deletes tenantbox.go's per-tenant keypair at a purge (KVPaths)",
	"internal/pki/platformbox.go":                  "kept: the platform keypair and the control-plane public keys, no tenant's",
	"internal/natsbootstrap/run.go":                "kept: the platform's public NATS trust copy",
	"internal/openbaokv/client.go":                 "the KV client library; its only user is internal/saasapicred",
	"internal/saasapicred/run.go":                  "kept: the SaaS API's NATS User JWT, the platform's credential",
	"internal/ingredients/sdb/openbao/provider.go": "not the platform's OpenBao: a sprout ingredient reading the customer's own vault",
}

// Every file that reads or writes OpenBao KV v2 (a "/data/" literal, the
// data endpoint, or an import of the internal/openbaokv client) is decided in
// kvUsers, and every kvUsers entry still is one. Exactly one of them is
// purged, and it is KVPaths' tenant keypair. A new KV user may hold
// tenant material: decide it.
func TestInventoryKV(t *testing.T) {
	root := filepath.Join("..", "..")
	found := map[string]bool{}
	for _, path := range goFiles(t) {
		if filepath.Base(filepath.Dir(path)) == "tenantpurge" {
			continue
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		rel = filepath.ToSlash(rel)
		uses := literalsOf(t, path, "github.com/yogzblr/imas/internal/openbaokv") != nil
		for _, lit := range literalsAll(t, path) {
			if strings.Contains(lit, "/data/") {
				uses = true
			}
		}
		if !uses {
			continue
		}
		found[rel] = true
		if _, ok := kvUsers[rel]; !ok {
			t.Errorf("%s uses OpenBao KV: decide whether it holds a tenant's material (kvUsers, tenantpurge.KVPaths)", rel)
		}
	}
	purged := 0
	for rel, why := range kvUsers {
		if !found[rel] {
			t.Errorf("kvUsers lists %s, which no longer uses OpenBao KV", rel)
		}
		if strings.HasPrefix(why, "purged") && rel != "internal/pki/tenantpurge.go" {
			purged++
		}
	}
	if purged != len(tenantpurge.KVPaths) || len(tenantpurge.KVPaths) != 1 || !strings.HasSuffix(tenantpurge.KVPaths[0], "/tenants/<tenant_id>") {
		t.Errorf("KVPaths %v and the purged KV users (%d) disagree", tenantpurge.KVPaths, purged)
	}
	if !found["internal/pki/tenantbox.go"] {
		t.Error("the tenant keypair's KV user was not found: the scan is broken")
	}
}

// literalsAll is every string literal of a file, import paths aside.
func literalsAll(t *testing.T, path string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var lits []string
	ast.Inspect(f, func(n ast.Node) bool {
		if _, ok := n.(*ast.ImportSpec); ok {
			return false
		}
		if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			if s, err := strconv.Unquote(bl.Value); err == nil {
				lits = append(lits, s)
			}
		}
		return true
	})
	return lits
}
