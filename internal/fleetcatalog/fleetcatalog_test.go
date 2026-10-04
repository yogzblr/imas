package fleetcatalog_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/fleetcatalog"
	"github.com/yogzblr/imas/internal/fleetcatalog/fleetcatalogtest"
)

func ptr(s string) *string { return &s }

func TestSQL(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	db := fleetcatalogtest.Open(t)
	deb := fleetcatalogtest.Signed(t, priv, "v2.4.1", "linux", "amd64", "deb")
	rpm := fleetcatalogtest.Signed(t, priv, "v2.4.1", "linux", "amd64", "rpm")
	msi := fleetcatalogtest.Signed(t, priv, "v2.4.1", "windows", "amd64", "msi")
	for _, r := range []fleetcatalog.Row{msi, rpm, deb, fleetcatalogtest.Signed(t, priv, "v2.5.0", "linux", "amd64", "deb")} {
		fleetcatalogtest.AddRow(t, db, r)
	}
	fleetcatalogtest.Approve(t, db, "t_acme", ptr("v2.4.1"))
	fleetcatalogtest.Approve(t, db, "t_other", ptr("v2.5.0"))
	fleetcatalogtest.Approve(t, db, "t_null", nil)
	cat := fleetcatalog.New(db)
	ctx := t.Context()

	t.Run("ApprovedVersion", func(t *testing.T) {
		for tenant, want := range map[string]string{"t_acme": "v2.4.1", "t_other": "v2.5.0", "t_null": "", "t_none": ""} {
			v, ok, err := cat.ApprovedVersion(ctx, tenant)
			if err != nil || v != want || ok != (want != "") {
				t.Errorf("%s: %q %v %v, want %q", tenant, v, ok, err, want)
			}
		}
	})
	t.Run("ReleaseRows", func(t *testing.T) {
		rows, err := cat.ReleaseRows(ctx, "v2.4.1")
		if err != nil || len(rows) != 3 {
			t.Fatalf("rows = %+v, %v", rows, err)
		}
		// Ordered by os, arch, package type, every field read back.
		for i, want := range []fleetcatalog.Row{deb, rpm, msi} {
			if rows[i] != want {
				t.Errorf("rows[%d] = %+v, want %+v", i, rows[i], want)
			}
		}
		if rows, err := cat.ReleaseRows(ctx, "v9.9.9"); err != nil || len(rows) != 0 {
			t.Errorf("unregistered: %+v, %v", rows, err)
		}
		fleetcatalogtest.Revoke(t, db, "v2.5.0")
		rows, _ = cat.ReleaseRows(ctx, "v2.5.0")
		if len(rows) != 1 || !rows[0].Revoked {
			t.Errorf("revoked rows = %+v", rows)
		}
	})
	t.Run("ApprovedManifest", func(t *testing.T) {
		m, found, err := cat.ApprovedManifest(ctx, "t_acme", "linux", "amd64", "rpm", "v2.4.1")
		if err != nil || !found || m != rpm.Manifest {
			t.Fatalf("got %+v %v %v", m, found, err)
		}
		// Another tenant's approval, a revoked version, no policy: none.
		for _, c := range [][2]string{{"t_acme", "v2.5.0"}, {"t_other", "v2.5.0"}, {"t_other", "v2.4.1"}, {"t_null", "v2.4.1"}} {
			if _, found, err := cat.ApprovedManifest(ctx, c[0], "linux", "amd64", "deb", c[1]); err != nil || found {
				t.Errorf("%s %s: found %v, %v", c[0], c[1], found, err)
			}
		}
	})
}

func TestInstall(t *testing.T) {
	t.Cleanup(func() { fleetcatalog.Install(nil) })
	if fleetcatalog.Current() != nil {
		t.Fatal("a catalog is installed by default")
	}
	cat := fleetcatalog.New(fleetcatalogtest.Open(t))
	fleetcatalog.Install(cat)
	if fleetcatalog.Current() != cat {
		t.Fatal("Install did not install")
	}
}

func TestSQL_RolloutWindow(t *testing.T) {
	db := fleetcatalogtest.Open(t)
	cat := fleetcatalog.New(db)
	ctx := t.Context()
	// Not UTC on the way in: the read hands back UTC either way.
	ist := time.FixedZone("IST", 5*3600+1800)
	aStart, aEnd := time.Date(2026, 10, 4, 9, 0, 0, 0, ist), time.Date(2026, 10, 4, 13, 0, 0, 0, ist)
	bStart, bEnd := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"t_a", "t_b", "t_nowin", "t_startonly", "t_endonly", "t_case"} {
		fleetcatalogtest.Approve(t, db, tenant, ptr("v2.4.1"))
	}
	fleetcatalogtest.SetWindow(t, db, "t_a", &aStart, &aEnd)
	fleetcatalogtest.SetWindow(t, db, "t_b", &bStart, &bEnd)
	fleetcatalogtest.SetWindow(t, db, "t_startonly", &aStart, nil)
	fleetcatalogtest.SetWindow(t, db, "t_endonly", nil, &aEnd)

	t.Run("no policy row", func(t *testing.T) {
		start, end, ok, err := cat.RolloutWindow(ctx, "t_none")
		if err != nil || ok || start != nil || end != nil {
			t.Fatalf("got %v %v %v %v", start, end, ok, err)
		}
	})
	t.Run("no window", func(t *testing.T) {
		start, end, ok, err := cat.RolloutWindow(ctx, "t_nowin")
		if err != nil || !ok || start != nil || end != nil {
			t.Fatalf("got %v %v %v %v", start, end, ok, err)
		}
	})
	// Two tenants with different windows: each read returns only its own.
	t.Run("each tenant's own window, in UTC", func(t *testing.T) {
		for tenant, want := range map[string][2]time.Time{"t_a": {aStart, aEnd}, "t_b": {bStart, bEnd}} {
			start, end, ok, err := cat.RolloutWindow(ctx, tenant)
			if err != nil || !ok || start == nil || end == nil {
				t.Fatalf("%s: got %v %v %v %v", tenant, start, end, ok, err)
			}
			if !start.Equal(want[0]) || !end.Equal(want[1]) {
				t.Errorf("%s: window [%s, %s), want [%s, %s)", tenant, start, end, want[0], want[1])
			}
			if start.Location() != time.UTC || end.Location() != time.UTC {
				t.Errorf("%s: not UTC: %v %v", tenant, start.Location(), end.Location())
			}
		}
	})
	t.Run("one NULL is corrupt, not no window", func(t *testing.T) {
		for _, tenant := range []string{"t_startonly", "t_endonly"} {
			start, end, ok, err := cat.RolloutWindow(ctx, tenant)
			if !errors.Is(err, fleetcatalog.ErrCorruptRolloutWindow) || ok || start != nil || end != nil {
				t.Errorf("%s: got %v %v %v %v, want ErrCorruptRolloutWindow", tenant, start, end, ok, err)
			}
		}
	})
	t.Run("failed read", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		start, end, ok, err := cat.RolloutWindow(cctx, "t_a")
		if err == nil || ok || start != nil || end != nil {
			t.Fatalf("got %v %v %v %v, want an error", start, end, ok, err)
		}
	})
	// The shared table (fleetcatalogtest.WindowCases), through the
	// database and the rule.
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	for _, tc := range fleetcatalogtest.WindowCases(now) {
		t.Run("case "+tc.Name, func(t *testing.T) {
			// The rule on its own.
			closed, err := fleetcatalog.RolloutWindowClosed(now, tc.Start, tc.End)
			if tc.Corrupt {
				if !errors.Is(err, fleetcatalog.ErrCorruptRolloutWindow) || closed {
					t.Errorf("RolloutWindowClosed = %v, %v; want ErrCorruptRolloutWindow", closed, err)
				}
			} else if err != nil || closed != tc.Closed {
				t.Errorf("RolloutWindowClosed = %v, %v; want %v", closed, err, tc.Closed)
			}

			// Through the database.
			fleetcatalogtest.SetWindow(t, db, "t_case", tc.Start, tc.End)
			start, end, ok, err := cat.RolloutWindow(ctx, "t_case")
			if tc.Corrupt {
				if !errors.Is(err, fleetcatalog.ErrCorruptRolloutWindow) || ok || start != nil || end != nil {
					t.Fatalf("got %v %v %v %v, want ErrCorruptRolloutWindow", start, end, ok, err)
				}
				return
			}
			if err != nil || !ok || (start == nil) != (tc.Start == nil) || (end == nil) != (tc.End == nil) {
				t.Fatalf("got %v %v %v %v", start, end, ok, err)
			}
			if start != nil && (!start.Equal(*tc.Start) || !end.Equal(*tc.End)) {
				t.Fatalf("read [%s, %s), wrote [%s, %s)", start, end, tc.Start, tc.End)
			}
			if closed, err := fleetcatalog.RolloutWindowClosed(now, start, end); err != nil || closed != tc.Closed {
				t.Errorf("read back: RolloutWindowClosed = %v, %v; want %v", closed, err, tc.Closed)
			}
		})
	}
}
