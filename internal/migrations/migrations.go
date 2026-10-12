// Package migrations holds the versioned schema migrations for imas's two
// PXC schemas, farmer and saas, and the checks around them (design doc
// docs/design/cloudxp-machine-manager-api-design.md §4.1a). cmd/migrate
// is the only thing that applies them: each set as its own schema's
// owner, so single writer per schema (§4.1) holds for DDL too. cmd/farmer
// and cmd/saasapi only read the version (WaitForSchema) and never change
// the schema.
//
// Rules for a new migration, which nothing here can enforce at runtime:
//
//   - Forward-only. No `-- +goose Down` section (a test refuses one).
//     A mistake is fixed by a later migration.
//   - Idempotent. MySQL DDL commits implicitly, so a migration that
//     fails halfway is left half applied and is re-run from the top: use
//     IF NOT EXISTS / IF EXISTS where MySQL has them, and the conditional
//     PREPARE idiom of saas/00002 where it doesn't.
//   - Backward compatible for one release (expand, then contract). The
//     previous release's farmer and saasapi keep running against the new
//     schema while the new pods roll out, and again after a helm
//     rollback. A contract step (drop or rename a column the previous
//     release still reads) waits a release, and when it lands it raises
//     that set's compatibleFrom below.
//   - PXC applies DDL in total order isolation: an ALTER on a big table
//     stalls writes cluster-wide for its duration. Schedule those.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"time"
)

//go:embed farmer/*.sql
var farmerFS embed.FS

//go:embed saas/*.sql
var saasFS embed.FS

// The oldest schema version, per set, whose binaries still run against
// this binary's latest schema: the floor `migrate up` records
// (imas_schema_info) and every binary checks itself against. Raise one
// only in the release whose migration breaks binaries built for an older
// schema version, to the version those binaries would need.
//
// Example: release N stops reading column x and ships schema version 7.
// Release N+1 drops x in migration 8 and sets compatibleFrom to 7, so
// release N (built for 7) still passes `migrate check` after a rollback,
// and release N-1 (built for 6, still reading x) doesn't.
//
// Why P21 slice 3 (farmer 00004 and 00005, saas 00008) left both floors
// alone: each of those migrations only creates a table (job_leases,
// sprout_user_jwt, saasapi_credential_state) and seeds rows in it. No
// column or table an older binary reads or writes is dropped, renamed or
// retyped, and no constraint it could violate is added to an existing
// table. A farmer built for schema 2, 3 or 4 and a saasapi built for 1 to
// 7 never name the new tables, so they run against the new schema exactly
// as before: during the rolling update and after a helm rollback, which is
// what the floor guards. What those older binaries keep on their own disk
// (sprout JWTs, saasapi's user JWT) is state, not schema; the floor cannot
// express it and does not need to, since an older release brings back the
// storage it used. The floor is raised by the release whose contract
// migration first drops something an older binary still uses, for example
// saas fleet_versions.signature, which saasapi still writes (as an empty string) and so
// stays until a release stops writing it. TestCompatibleFromReviewed
// fails on any new migration until its effect on the floor is decided.
const (
	farmerCompatibleFrom = 2
	saasCompatibleFrom   = 1
)

// VersionTable is goose's own version table (goose.DefaultTablename),
// one in each schema.
const VersionTable = "goose_db_version"

// InfoTable records, in each schema, the compatibility floor `migrate
// up` raised it to. One row, id 1. cmd/migrate creates it as the schema
// owner, outside goose, because the floor is written before the
// migrations run.
const InfoTable = "imas_schema_info"

// Set is one schema's migrations.
type Set struct {
	name           string
	fsys           fs.FS
	versions       []int64 // every file's version, ascending
	latest         int64
	compatibleFrom int64
}

var (
	// Farmer is the farmer schema's set, applied as farmer's own user.
	Farmer = mustSet("farmer", farmerFS, farmerCompatibleFrom)
	// Saas is the saas schema's set, applied as saasapi's own user.
	Saas = mustSet("saas", saasFS, saasCompatibleFrom)
)

func mustSet(name string, embedded embed.FS, compatibleFrom int64) Set {
	s, err := newSet(name, embedded, name, compatibleFrom)
	if err != nil {
		panic(err)
	}
	return s
}

func newSet(name string, fsys fs.FS, dir string, compatibleFrom int64) (Set, error) {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		return Set{}, fmt.Errorf("migrations %s: %w", name, err)
	}
	versions, err := Versions(sub)
	if err != nil {
		return Set{}, fmt.Errorf("migrations %s: %w", name, err)
	}
	if len(versions) == 0 {
		return Set{}, fmt.Errorf("migrations %s: no migrations", name)
	}
	latest := versions[len(versions)-1]
	if compatibleFrom < 1 || compatibleFrom > latest {
		return Set{}, fmt.Errorf("migrations %s: compatibleFrom %d is outside 1..%d", name, compatibleFrom, latest)
	}
	return Set{name: name, fsys: sub, versions: versions, latest: latest, compatibleFrom: compatibleFrom}, nil
}

// Versions returns the version of each NNNNN_name.sql file in fsys, in
// ascending order. goose would accept other names; this package doesn't,
// so every set reads the same way.
func Versions(fsys fs.FS) ([]int64, error) {
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, err
	}
	seen := map[int64]string{}
	var out []int64
	for _, n := range names { // fs.Glob sorts, and the prefix is zero-padded
		prefix, _, ok := strings.Cut(path.Base(n), "_")
		if !ok || len(prefix) != 5 {
			return nil, fmt.Errorf("%s: want NNNNN_name.sql", n)
		}
		v, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil || v < 1 {
			return nil, fmt.Errorf("%s: want NNNNN_name.sql", n)
		}
		if prev, dup := seen[v]; dup {
			return nil, fmt.Errorf("%s and %s share version %d", prev, n, v)
		}
		seen[v] = n
		out = append(out, v)
	}
	return out, nil
}

// Name is the set's name, "farmer" or "saas". The schema's actual name
// comes from the DSN.
func (s Set) Name() string { return s.name }

// FS is the set's migration files.
func (s Set) FS() fs.FS { return s.fsys }

// Latest is the newest version this binary carries, and the version its
// farmer or saasapi needs.
func (s Set) Latest() int64 { return s.latest }

// CompatibleFrom is the floor `migrate up` records; see compatibleFrom.
func (s Set) CompatibleFrom() int64 { return s.compatibleFrom }

// State is what a schema records about its own version.
type State struct {
	// Version is the newest applied migration, 0 when none is.
	Version int64
	// Floor is the oldest binary schema version the schema still
	// supports, 0 when none is recorded.
	Floor int64
	// Missing is the lowest of a set's own versions, up to its Latest,
	// that isn't applied although a newer one is; 0 when there is none.
	// Only Set.ReadState fills it: versions can be applied out of order
	// (saas 00008 before 00007), so Version alone can't show a gap below
	// it, as after a `migrate up` that failed on the lower version.
	Missing int64
}

var (
	// ErrSchemaBehind: the schema hasn't been migrated to the version
	// this binary needs yet. Expected briefly on install, where the
	// migration runs after the services start.
	ErrSchemaBehind = errors.New("schema is behind this binary")
	// ErrSchemaTooNew: the schema was migrated past what this binary can
	// run against (a contract migration raised the floor above it).
	ErrSchemaTooNew = errors.New("schema is too new for this binary")
)

// Check reports whether a binary carrying this set can run against a
// schema in state st: the schema is at least at Latest, none of the
// set's versions up to Latest is missing below it, and its floor doesn't
// exclude Latest. A schema ahead of Latest is fine as long as
// the floor allows it; that's the rollback case.
func (s Set) Check(st State) error {
	switch {
	case st.Version < s.latest:
		return fmt.Errorf("%s: %w: schema version %d, this binary needs %d", s.name, ErrSchemaBehind, st.Version, s.latest)
	case st.Missing != 0:
		return fmt.Errorf("%s: %w: schema version %d lacks migration %d, which this binary needs", s.name, ErrSchemaBehind, st.Version, st.Missing)
	case st.Floor > s.latest:
		return fmt.Errorf("%s: %w: schema version %d supports binaries built for %d or later, this binary is built for %d",
			s.name, ErrSchemaTooNew, st.Version, st.Floor, s.latest)
	}
	return nil
}

// ReadState is the package's ReadState plus Missing: which of this set's
// versions, up to Latest, the schema lacks. A version above Latest is
// another binary's and isn't looked for, so a rollback's older binary is
// judged by its own migrations only.
func (s Set) ReadState(ctx context.Context, db *sql.DB) (State, error) {
	st, err := ReadState(ctx, db)
	if err != nil || st.Version == 0 {
		return st, err
	}
	applied, err := appliedVersions(ctx, db)
	if err != nil {
		return st, err
	}
	st.Missing = s.missing(applied, st.Version)
	return st, nil
}

// missing is the lowest of the set's versions up to Latest, and below
// version (the schema's newest), that applied lacks; 0 if none.
func (s Set) missing(applied map[int64]bool, version int64) int64 {
	for _, v := range s.versions {
		if v > s.latest || v >= version {
			break
		}
		if !applied[v] {
			return v
		}
	}
	return 0
}

// appliedVersions reads every applied version from goose's table, by the
// same rule ReadState's Version uses. The table exists: the caller saw a
// version in it.
func appliedVersions(ctx context.Context, db *sql.DB) (map[int64]bool, error) {
	rows, err := db.QueryContext(ctx, "SELECT v.version_id FROM `"+VersionTable+"` v"+
		" WHERE v.is_applied AND v.id = (SELECT MAX(w.id) FROM `"+VersionTable+"` w WHERE w.version_id = v.version_id)")
	if err != nil {
		return nil, fmt.Errorf("reading applied schema versions: %w", err)
	}
	defer rows.Close()
	applied := map[int64]bool{}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("reading applied schema versions: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading applied schema versions: %w", err)
	}
	return applied, nil
}

// ReadState reads st from the schema db is connected to, without
// creating or changing anything: a missing version table reads as
// version 0 and a missing floor as 0. (goose's own GetDBVersion creates
// the version table, so it isn't used here.)
func ReadState(ctx context.Context, db *sql.DB) (State, error) {
	var st State
	ok, err := tableExists(ctx, db, VersionTable)
	if err != nil {
		return st, err
	}
	if ok {
		// The newest version whose latest row is applied. cmd/migrate never
		// rolls back, but a row goose wrote for a manual down would flip
		// is_applied, and that version doesn't count.
		err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(v.version_id), 0) FROM `"+VersionTable+"` v"+
			" WHERE v.is_applied AND v.id = (SELECT MAX(w.id) FROM `"+VersionTable+"` w WHERE w.version_id = v.version_id)").
			Scan(&st.Version)
		if err != nil {
			return st, fmt.Errorf("reading schema version: %w", err)
		}
	}
	ok, err = tableExists(ctx, db, InfoTable)
	if err != nil {
		return st, err
	}
	if ok {
		err := db.QueryRowContext(ctx, "SELECT min_compatible_version FROM `"+InfoTable+"` WHERE id = 1").Scan(&st.Floor)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return st, fmt.Errorf("reading schema compatibility floor: %w", err)
		}
	}
	return st, nil
}

func tableExists(ctx context.Context, db *sql.DB, table string) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?", table).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("looking up table %s: %w", table, err)
	}
	return n > 0, nil
}

// Wait backoff for WaitForSchema: 1s, doubling, at most 30s apart.
const (
	waitInitial = time.Second
	waitMax     = 30 * time.Second
)

// WaitForSchema blocks until the schema db is connected to passes
// s.Check, retrying with backoff on a failed check or a failed read, and
// logging each retry with logf. It returns ctx's error if ctx ends first.
// farmer and saasapi call it at startup, before serving: on install the
// migration runs after them, and during an upgrade a pod can start
// before the hook Job finishes.
func WaitForSchema(ctx context.Context, db *sql.DB, s Set, logf func(format string, args ...any)) error {
	return waitForSchema(ctx, func(ctx context.Context) (State, error) { return s.ReadState(ctx, db) }, s, logf, waitInitial, waitMax)
}

func waitForSchema(ctx context.Context, read func(context.Context) (State, error), s Set,
	logf func(string, ...any), delay, maxDelay time.Duration,
) error {
	for {
		st, err := read(ctx)
		if err == nil {
			if err = s.Check(st); err == nil {
				return nil
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		logf("waiting for the %s schema: %v (retrying in %s)", s.name, err, delay)
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		delay = min(2*delay, maxDelay)
	}
}
