package pki

import (
	"testing"
	"time"
)

// UseInMemoryJoinToken works in a test binary (testing.Testing) and its
// restore puts the previous store back. Outside one it panics; that
// branch can't run here.
func TestUseInMemoryJoinTokenUnderTest(t *testing.T) {
	orig := enrollKeyStore
	restore := UseInMemoryJoinToken("ek_seam.secret", "t1", 2)
	m, ok := enrollKeyStore.(*memoryEnrollmentKeyStore)
	if !ok {
		restore()
		t.Fatalf("enrollKeyStore = %T, want the in-memory store", enrollKeyStore)
	}
	row, err := m.lookup("ek_seam")
	if err != nil {
		t.Fatal(err)
	}
	if row.TenantID != "t1" || row.MaxUses != 2 || row.KeyHash != hashSecret("secret") || !row.Expiry.After(time.Now()) {
		t.Errorf("in-memory join token row = %+v", row)
	}
	restore()
	if enrollKeyStore != orig {
		t.Errorf("restore left enrollKeyStore = %T", enrollKeyStore)
	}
}
