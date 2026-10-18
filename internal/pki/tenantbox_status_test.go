package pki

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Unit T5 (L19): a KV write is written only when OpenBao answers 2xx. A
// 3xx the client does not follow (an empty 308 from an ingress) used to
// read as an empty success, and farmer then used a tenant keypair that
// was never stored.
func TestTenantBoxWriteNeeds2xx(t *testing.T) {
	for _, c := range []struct {
		status  int
		written bool
	}{
		{http.StatusOK, true},
		{http.StatusNoContent, true},
		{http.StatusPermanentRedirect, false},
		{http.StatusMultipleChoices, false},
		{http.StatusSeeOther, false},
		{http.StatusNotModified, false},
	} {
		t.Run(http.StatusText(c.status), func(t *testing.T) {
			var reads, writes atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.URL.Path, "/v1/secret/data/imas/tenant-x25519/tenants/") {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				switch r.Method {
				case http.MethodGet:
					reads.Add(1)
					w.WriteHeader(http.StatusNotFound)
					w.Write([]byte(`{"errors":[]}`))
				case http.MethodPut, http.MethodPost:
					writes.Add(1)
					if c.status == http.StatusPermanentRedirect {
						w.Header().Set("Location", "/v1/elsewhere")
					}
					w.WriteHeader(c.status)
					if c.status == http.StatusOK {
						w.Write([]byte(`{"data":{"version":1}}`))
					}
				}
			}))
			defer srv.Close()
			t.Setenv(EnvTenantBoxOpenBaoAddr, srv.URL)
			t.Setenv(EnvTenantBoxOpenBaoAllowInsecure, "true")
			t.Setenv(EnvTenantBoxOpenBaoKVMount, "")
			t.Setenv(EnvTenantBoxOpenBaoKVPath, "")
			t.Setenv(EnvTenantBoxOpenBaoAuthMethod, TenantBoxAuthMethodToken)
			t.Setenv(EnvTenantBoxOpenBaoToken, "tok")

			client, err := newTenantBoxClientFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var pub, priv [32]byte
			written, err := client.writeKeypair(t.Context(), client.tenantPath("t_status"), &pub, &priv, 0, nil)
			if written != c.written {
				t.Fatalf("written = %v, %v; want %v", written, err, c.written)
			}
			if c.written && err != nil {
				t.Fatalf("2xx: err = %v", err)
			}
			if !c.written && !errors.Is(err, ErrTenantBoxWriteFailed) {
				t.Fatalf("%d: err = %v, want ErrTenantBoxWriteFailed", c.status, err)
			}

			if c.written {
				return
			}
			// Through the public path: no key is handed out for a write
			// that never happened.
			resetTenantX25519KeypairCache()
			t.Cleanup(resetTenantX25519KeypairCache)
			if pub, err := GetTenantX25519PublicKey("t_status"); err == nil {
				t.Fatalf("GetTenantX25519PublicKey = %q after an unfollowed %d on the write", pub, c.status)
			}
		})
	}
}
