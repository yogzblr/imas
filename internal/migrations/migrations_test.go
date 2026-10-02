package migrations

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/pressly/goose/v3"
)

func TestVersionTableIsGooses(t *testing.T) {
	if VersionTable != goose.DefaultTablename {
		t.Fatalf("VersionTable %q, goose writes %q", VersionTable, goose.DefaultTablename)
	}
}

// TestEmbeddedSets: both sets load (mustSet would have panicked at init
// otherwise) and agree with their files. goose parses the SQL itself
// only when it runs it; the MySQL tests do that.
func TestEmbeddedSets(t *testing.T) {
	for _, s := range []Set{Farmer, Saas} {
		versions, err := Versions(s.FS())
		if err != nil {
			t.Fatalf("%s: %v", s.Name(), err)
		}
		if got := versions[len(versions)-1]; got != s.Latest() {
			t.Errorf("%s: Latest %d, newest file %d", s.Name(), s.Latest(), got)
		}
		if s.CompatibleFrom() < 1 || s.CompatibleFrom() > s.Latest() {
			t.Errorf("%s: CompatibleFrom %d outside 1..%d", s.Name(), s.CompatibleFrom(), s.Latest())
		}
	}
}

// TestMigrationsAreForwardOnly enforces the package's first rule: no
// down migrations, ever.
func TestMigrationsAreForwardOnly(t *testing.T) {
	for _, s := range []Set{Farmer, Saas} {
		names, _ := fs.Glob(s.FS(), "*.sql")
		for _, n := range names {
			b, err := fs.ReadFile(s.FS(), n)
			if err != nil {
				t.Fatal(err)
			}
			body := string(b)
			if !strings.Contains(body, "-- +goose Up") {
				t.Errorf("%s/%s: no -- +goose Up", s.Name(), n)
			}
			if strings.Contains(strings.ToLower(body), "+goose down") {
				t.Errorf("%s/%s: has a down section; migrations are forward-only", s.Name(), n)
			}
		}
	}
}

func TestVersions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []string
		want  []int64
		bad   bool
	}{
		{"ordered", []string{"00002_b.sql", "00001_a.sql", "00010_c.sql"}, []int64{1, 2, 10}, false},
		{"gap", []string{"00001_a.sql", "00003_c.sql"}, []int64{1, 3}, false},
		{"not padded", []string{"1_a.sql"}, nil, true},
		{"zero", []string{"00000_a.sql"}, nil, true},
		{"not a number", []string{"0000a_a.sql"}, nil, true},
		{"no name", []string{"00001.sql"}, nil, true},
		{"duplicate version", []string{"00001_a.sql", "00001_b.sql"}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := fstest.MapFS{}
			for _, f := range tc.files {
				m[f] = &fstest.MapFile{Data: []byte("-- +goose Up\nSELECT 1;\n")}
			}
			got, err := Versions(m)
			if tc.bad {
				if err == nil {
					t.Fatalf("want an error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestNewSetCompatibleFromInRange(t *testing.T) {
	m := fstest.MapFS{
		"x/00001_a.sql": {Data: []byte("-- +goose Up\nSELECT 1;\n")},
		"x/00002_b.sql": {Data: []byte("-- +goose Up\nSELECT 1;\n")},
	}
	for cf, ok := range map[int64]bool{0: false, 1: true, 2: true, 3: false} {
		_, err := newSet("x", m, "x", cf)
		if (err == nil) != ok {
			t.Errorf("compatibleFrom %d: err %v, want ok=%v", cf, err, ok)
		}
	}
	if _, err := newSet("x", fstest.MapFS{"x/README": {}}, "x", 1); err == nil {
		t.Error("a set with no migrations loaded")
	}
}

func testSet(latest, compatibleFrom int64) Set {
	return Set{name: "test", latest: latest, compatibleFrom: compatibleFrom}
}

func TestCheck(t *testing.T) {
	s := testSet(5, 3)
	for _, tc := range []struct {
		name string
		st   State
		want error
	}{
		{"fresh schema", State{}, ErrSchemaBehind},
		{"one behind", State{Version: 4, Floor: 3}, ErrSchemaBehind},
		{"current", State{Version: 5, Floor: 3}, nil},
		{"current, floor unrecorded", State{Version: 5}, nil},
		{"floor at this binary", State{Version: 5, Floor: 5}, nil},
		{"ahead, still supports this binary (rollback)", State{Version: 7, Floor: 5}, nil},
		{"ahead, floor past this binary", State{Version: 7, Floor: 6}, ErrSchemaTooNew},
		{"behind and floor past this binary", State{Version: 4, Floor: 6}, ErrSchemaBehind},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Check(tc.st)
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("Check(%+v) = %v, want %v", tc.st, err, tc.want)
			}
		})
	}
}

func TestWaitForSchemaRetriesUntilCurrent(t *testing.T) {
	s := testSet(2, 1)
	reads := []struct {
		st  State
		err error
	}{
		{err: errors.New("connection refused")},
		{st: State{Version: 0}},
		{st: State{Version: 1, Floor: 1}},
		{st: State{Version: 2, Floor: 1}},
	}
	i := 0
	read := func(context.Context) (State, error) {
		r := reads[i]
		i++
		return r.st, r.err
	}
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, format) }
	if err := waitForSchema(context.Background(), read, s, logf, time.Millisecond, 2*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if i != len(reads) {
		t.Fatalf("read %d times, want %d", i, len(reads))
	}
	if len(logged) != len(reads)-1 {
		t.Fatalf("logged %d retries, want %d", len(logged), len(reads)-1)
	}
}

func TestWaitForSchemaStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	read := func(context.Context) (State, error) { return State{}, nil } // never current
	err := waitForSchema(ctx, read, testSet(1, 1), func(string, ...any) {}, time.Millisecond, 5*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want the context's error", err)
	}
}

// TestWaitForSchemaTooNewKeepsWaiting: a binary too old for the schema
// doesn't exit; it waits (and says why), since the rollout that started
// it may still replace it.
func TestWaitForSchemaTooNewKeepsWaiting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	var last string
	logf := func(format string, args ...any) { last = args[1].(error).Error() }
	read := func(context.Context) (State, error) { return State{Version: 9, Floor: 8}, nil }
	if err := waitForSchema(ctx, read, testSet(5, 1), logf, time.Millisecond, time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(last, ErrSchemaTooNew.Error()) {
		t.Fatalf("last retry logged %q, want it to name %q", last, ErrSchemaTooNew)
	}
}
