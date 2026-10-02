package fleetcatalog_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

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
