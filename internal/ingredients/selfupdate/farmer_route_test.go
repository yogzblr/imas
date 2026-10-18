package selfupdate

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/api/handlers"
	"github.com/yogzblr/imas/internal/fleetsign"
)

// memDBSeq numbers this package's in-memory sqlite test databases, so
// a DSN never repeats across `go test -count=N` runs of the same test.
var memDBSeq atomic.Int64

// A fleet update through farmer's own manifest route (docs/briefs/
// E-followups.md, Z item 3): the release as saasapi registers it (its
// fleet_versions row and its GPG-signed checksums.txt), farmer's
// production catalog SQL and GET /v1/sprout/update-manifest handler
// (installed by handlers.SetReadinessDB, as cmd/farmer does), and the
// sprout's verification against its shipped keyring. The rest of this
// package's tests serve the manifest from a fake farmer; this one shows
// the bytes farmer actually serves verify, and that farmer, which checks
// no signature (D20), still cannot get a release signed by another key
// installed. The gateway JWT check in front of the handler is
// internal/api's (update_manifest_test.go); here the request carries the
// identity Auth would have set.
func TestApply_ThroughFarmerManifestRoute(t *testing.T) {
	for _, tc := range []struct {
		name    string
		signer  func(*fixture) // nil: the release key the keyring holds
		wantErr error
	}{
		{name: "signed by the release key"},
		{name: "signed by another key", signer: func(f *fixture) { f.signer = newReleaseKey(t) }, wantErr: fleetsign.ErrBadSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.signer != nil {
				tc.signer(f)
			}
			txt := strings.Repeat("4", 64) + "  imas_2.4.1_linux_amd64.tar.gz\n" +
				f.manifest.ChecksumSHA256 + "  " + testFileDeb + "\n"
			sig := base64.StdEncoding.EncodeToString(detachSign(t, f.signer, []byte(txt)))

			db := releaseDB(t)
			mustExec(t, db, `INSERT INTO saas.fleet_versions
				(id, version, os, arch, package_type, file_name, checksum_sha256, min_sprout_version, signature, revoked, released_at)
				VALUES ('r1', ?, 'linux', 'amd64', 'deb', ?, ?, ?, '', 0, ?)`,
				testTarget, testFileDeb, f.manifest.ChecksumSHA256, f.manifest.MinSproutVersion, time.Now())
			mustExec(t, db, `INSERT INTO saas.fleet_release_checksums (version, checksums_txt, checksums_sig, created_at) VALUES (?, ?, ?, ?)`,
				testTarget, txt, sig, time.Now())
			mustExec(t, db, `INSERT INTO saas.tenant_update_policy (tenant_id, approved_version, auto_update) VALUES ('t_acme', ?, 0)`, testTarget)
			handlers.SetReadinessDB(db)
			t.Cleanup(func() { handlers.SetReadinessDB(nil) })
			id := handlers.SproutIdentity{TenantID: "t_acme", SproutID: "web-01"}
			f.farmerRoute = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlers.GetSproutUpdateManifest(w, r.WithContext(handlers.WithSproutIdentity(r.Context(), id)))
			})

			res, err := step(t, target(testTarget)).Apply(context.Background())
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Apply = %+v, %v; want %v", res, err, tc.wantErr)
				}
				if len(f.calls) != 0 || len(f.repoReqs) != 0 {
					t.Fatalf("refused release still downloaded (%d) or installed (%+v)", len(f.repoReqs), f.calls)
				}
				return
			}
			if err != nil || !res.Succeeded || !res.Changed {
				t.Fatalf("Apply = %+v, %v; want success", res, err)
			}
			if len(f.farmerReqs) != 1 {
				t.Fatalf("farmer got %d manifest requests, want 1", len(f.farmerReqs))
			}
			if len(f.calls) == 0 || !strings.HasSuffix(f.calls[0].name, "dpkg") {
				t.Fatalf("not installed with dpkg: %+v", f.calls)
			}
		})
	}
}

// releaseDB is farmer's database handle with the saas tables the manifest
// SQL reads (internal/fleetcatalog), in the shape of the saas migrations.
func releaseDB(t *testing.T) *gorm.DB {
	t.Helper()
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "-" + strconv.FormatInt(memDBSeq.Add(1), 10)
	db, err := gorm.Open(sqlite.Open("file:"+name+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	mustExec(t, db, `ATTACH DATABASE 'file:`+name+`_saas?mode=memory&cache=shared' AS saas`)
	mustExec(t, db, `CREATE TABLE saas.fleet_versions (
		id varchar(32) PRIMARY KEY,
		version varchar(64) NOT NULL,
		os varchar(32) NOT NULL,
		arch varchar(32) NOT NULL,
		package_type varchar(16) NOT NULL,
		file_name varchar(255) NOT NULL,
		checksum_sha256 varchar(64) NOT NULL,
		min_sprout_version varchar(64) NOT NULL,
		signature varchar(128) NOT NULL DEFAULT '',
		revoked tinyint(1) NOT NULL DEFAULT 0,
		released_at datetime NOT NULL,
		notes text,
		UNIQUE (version, os, arch, package_type))`)
	mustExec(t, db, `CREATE TABLE saas.fleet_release_checksums (
		version varchar(64) PRIMARY KEY,
		checksums_txt mediumtext NOT NULL,
		checksums_sig text NOT NULL,
		created_at datetime NOT NULL)`)
	mustExec(t, db, `CREATE TABLE saas.tenant_update_policy (
		tenant_id varchar(32) PRIMARY KEY,
		approved_version varchar(64) DEFAULT NULL,
		auto_update tinyint(1) NOT NULL DEFAULT 0,
		rollout_window_start datetime DEFAULT NULL,
		rollout_window_end datetime DEFAULT NULL,
		updated_at datetime DEFAULT NULL)`)
	return db
}

func mustExec(t *testing.T, db *gorm.DB, q string, args ...any) {
	t.Helper()
	if err := db.Exec(q, args...).Error; err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}
