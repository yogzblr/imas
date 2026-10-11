package pki

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nats-io/nkeys"
)

func TestSeedNATSKeysLocationsAndPrefixes(t *testing.T) {
	setupTestPKI(t)
	ctx := context.Background()
	const tenant = "t-seam"

	cases := []struct {
		ref    natsKeyRef
		path   string
		prefix nkeys.PrefixByte
	}{
		{natsKeyRef{role: natsKeyOperator}, filepath.Join(natsAuthDir(), "operator.nk"), nkeys.PrefixByteOperator},
		{natsKeyRef{role: natsKeyOperatorSigning}, filepath.Join(natsAuthDir(), "operator-signing.nk"), nkeys.PrefixByteOperator},
		{natsKeyRef{role: natsKeySysAccount}, filepath.Join(natsAuthDir(), "sys-account.nk"), nkeys.PrefixByteAccount},
		{natsKeyRef{role: natsKeyTenantAccount}, filepath.Join(natsAuthDir(), "tenant.nk"), nkeys.PrefixByteAccount},
		{natsKeyRef{role: natsKeyTenantSigning}, filepath.Join(natsAuthDir(), "tenant-signing.nk"), nkeys.PrefixByteAccount},
		{natsKeyRef{role: natsKeyTenantAccount, tenantID: tenant}, tenantAccountKeyPath(tenant), nkeys.PrefixByteAccount},
		{natsKeyRef{role: natsKeyTenantSigning, tenantID: tenant}, tenantAccountSigningKeyPath(tenant), nkeys.PrefixByteAccount},
	}
	ks := seedNATSKeys{}
	for _, c := range cases {
		t.Run(c.ref.String(), func(t *testing.T) {
			if _, err := ks.keyPair(ctx, c.ref); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("keyPair before ensure: err = %v, want fs.ErrNotExist", err)
			}
			if _, err := os.Stat(c.path); !os.IsNotExist(err) {
				t.Fatalf("keyPair created %s (stat err %v)", c.path, err)
			}

			kp, err := ks.ensureKeyPair(ctx, c.ref)
			if err != nil {
				t.Fatalf("ensureKeyPair: %v", err)
			}
			pub, _ := kp.PublicKey()
			if p := nkeys.Prefix(pub); p != c.prefix {
				t.Errorf("public key %q has prefix %v, want %v", pub, p, c.prefix)
			}
			info, err := os.Stat(c.path)
			if err != nil {
				t.Fatalf("seed file %s not written: %v", c.path, err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Errorf("%s perm %v, want 0600", c.path, info.Mode().Perm())
			}

			for name, get := range map[string]func(context.Context, natsKeyRef) (nkeys.KeyPair, error){
				"keyPair": ks.keyPair, "ensureKeyPair": ks.ensureKeyPair,
			} {
				again, err := get(ctx, c.ref)
				if err != nil {
					t.Fatalf("%s after create: %v", name, err)
				}
				if p2, _ := again.PublicKey(); p2 != pub {
					t.Errorf("%s returned %q, want the created key %q", name, p2, pub)
				}
			}
		})
	}
}

func TestSeedNATSKeysExternalSeed(t *testing.T) {
	setupTestPKI(t)
	ctx := context.Background()
	const tenant = "t-ext"

	want, _ := nkeys.CreateAccount()
	wantPub, _ := want.PublicKey()
	seed, _ := want.Seed()
	seedFile := filepath.Join(t.TempDir(), "signing.seed")
	if err := os.WriteFile(seedFile, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IMAS_NATS_TENANT_T_EXT_SIGNING_SEED_FILE", seedFile)

	ref := natsKeyRef{role: natsKeyTenantSigning, tenantID: tenant}
	for name, get := range map[string]func(context.Context, natsKeyRef) (nkeys.KeyPair, error){
		"keyPair": seedNATSKeys{}.keyPair, "ensureKeyPair": seedNATSKeys{}.ensureKeyPair,
	} {
		kp, err := get(ctx, ref)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if pub, _ := kp.PublicKey(); pub != wantPub {
			t.Errorf("%s returned %q, want the external seed's %q", name, pub, wantPub)
		}
	}
	if _, err := os.Stat(tenantAccountSigningKeyPath(tenant)); !os.IsNotExist(err) {
		t.Errorf("external seed was copied to disk (stat err %v)", err)
	}
}

func TestSeedNATSKeysUnknownRole(t *testing.T) {
	setupTestPKI(t)
	ref := natsKeyRef{role: natsKeyRole(99)}
	if _, err := (seedNATSKeys{}).ensureKeyPair(context.Background(), ref); err == nil {
		t.Error("ensureKeyPair accepted an unknown role")
	}
	if _, err := (seedNATSKeys{}).keyPair(context.Background(), ref); err == nil {
		t.Error("keyPair accepted an unknown role")
	}
}

// recordingNATSKeys records which keys were requested and delegates to
// the seed provider.
type recordingNATSKeys struct {
	seedNATSKeys
	ensured []string
}

func (r *recordingNATSKeys) ensureKeyPair(ctx context.Context, k natsKeyRef) (nkeys.KeyPair, error) {
	r.ensured = append(r.ensured, k.String())
	return r.seedNATSKeys.ensureKeyPair(ctx, k)
}

// The farmer obtains every trust chain pair through natsKeys, so PR4b can
// swap the provider without touching the signing code.
func TestTrustChainPairsComeFromProvider(t *testing.T) {
	setupTestPKI(t)
	rec := &recordingNATSKeys{}
	prev := natsKeys
	natsKeys = rec
	t.Cleanup(func() { natsKeys = prev })

	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatalf("ensureNatsAuth: %v", err)
	}
	want := []string{"operator", "operator-signing", "sys-account", "tenant-account", "tenant-signing"}
	if !slices.Equal(rec.ensured, want) {
		t.Errorf("ensureNatsAuth requested %v, want %v", rec.ensured, want)
	}

	rec.ensured = nil
	tenantAuthMu.Lock()
	_, _, err = ensureTenantAccountMaterial(mat, "t-seam", "t-seam")
	tenantAuthMu.Unlock()
	if err != nil {
		t.Fatalf("ensureTenantAccountMaterial: %v", err)
	}
	want = []string{"tenant-account/t-seam", "tenant-signing/t-seam"}
	if !slices.Equal(rec.ensured, want) {
		t.Errorf("ensureTenantAccountMaterial requested %v, want %v", rec.ensured, want)
	}
}
