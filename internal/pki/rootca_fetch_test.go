package pki

import (
	"bytes"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yogzblr/imas/internal/config"
)

// serveRootCA points FetchRootCA at a TLS test server running handler,
// restoring the farmer address afterwards, and returns how many requests
// the server has seen.
func serveRootCA(t *testing.T, handler http.HandlerFunc) *atomic.Int64 {
	t.Helper()
	var hits atomic.Int64
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(ts.Close)
	host, port, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	oldIface, oldPort := config.FarmerInterface, config.FarmerAPIPort
	config.FarmerInterface, config.FarmerAPIPort = host, port
	t.Cleanup(func() { config.FarmerInterface, config.FarmerAPIPort = oldIface, oldPort })
	return &hits
}

// useSproutRootCA points config.SproutRootCA at path and sets
// config.SproutRootCATOFU, restoring both afterwards.
func useSproutRootCA(t *testing.T, path string, tofu bool) {
	t.Helper()
	oldCA, oldTOFU := config.SproutRootCA, config.SproutRootCATOFU
	config.SproutRootCA, config.SproutRootCATOFU = path, tofu
	t.Cleanup(func() { config.SproutRootCA, config.SproutRootCATOFU = oldCA, oldTOFU })
}

// assertNothingPinned fails unless dir is empty: no CA file and no
// leftover temporary file.
func assertNothingPinned(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("unexpected file left behind: %s", e.Name())
	}
}

func TestFetchRootCA_RejectsBadResponses(t *testing.T) {
	cert := generateSelfSignedCertPEM(t)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})
	badDER := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")})

	tests := []struct {
		name   string
		status int
		body   []byte
	}{
		// What the DMZ Envoy returns for /auth/cert/ today: no such route,
		// so the request falls to the jwt_authn-gated default route.
		{"envoy 401 Jwt is missing", http.StatusUnauthorized, []byte("Jwt is missing")},
		// A non-200 is rejected even when the body happens to be a cert.
		{"non-200 with cert body", http.StatusInternalServerError, cert},
		{"404", http.StatusNotFound, []byte("404 page not found\n")},
		{"200 empty body", http.StatusOK, nil},
		{"200 whitespace only", http.StatusOK, []byte("\n \n")},
		{"200 plain text", http.StatusOK, []byte("Jwt is missing")},
		{"200 html error page", http.StatusOK, []byte("<html><body>Service Unavailable</body></html>")},
		{"200 private key block", http.StatusOK, keyPEM},
		{"200 undecodable certificate", http.StatusOK, badDER},
		{"200 text before cert", http.StatusOK, append([]byte("Jwt is missing\n"), cert...)},
		{"200 text after cert", http.StatusOK, append(append([]byte{}, cert...), []byte("trailing junk")...)},
		{"200 cert then key", http.StatusOK, append(append([]byte{}, cert...), keyPEM...)},
		{"200 truncated cert", http.StatusOK, cert[:len(cert)/2]},
		{"200 oversized", http.StatusOK, bytes.Repeat(cert, maxRootCABytes/len(cert)+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serveRootCA(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				w.Write(tt.body)
			})
			dir := t.TempDir()
			err := FetchRootCA(filepath.Join(dir, "tls-rootca.pem"))
			if !errors.Is(err, ErrRootCAFetch) {
				t.Fatalf("FetchRootCA error = %v, want ErrRootCAFetch", err)
			}
			assertNothingPinned(t, dir)
		})
	}
}

func TestFetchRootCA_ErrorQuotesResponse(t *testing.T) {
	serveRootCA(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Jwt is missing", http.StatusUnauthorized)
	})
	err := FetchRootCA(filepath.Join(t.TempDir(), "tls-rootca.pem"))
	if err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "Jwt is missing") {
		t.Fatalf("error should name the status and body, got: %v", err)
	}
}

func TestFetchRootCA_DoesNotFollowRedirects(t *testing.T) {
	cert := generateSelfSignedCertPEM(t)
	hits := serveRootCA(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			w.Write(cert)
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	dir := t.TempDir()
	if err := FetchRootCA(filepath.Join(dir, "tls-rootca.pem")); !errors.Is(err, ErrRootCAFetch) {
		t.Fatalf("FetchRootCA error = %v, want ErrRootCAFetch", err)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("server saw %d requests, want 1 (redirect must not be followed)", n)
	}
	assertNothingPinned(t, dir)
}

func TestFetchRootCA_PinsValidBundleVerbatim(t *testing.T) {
	bundle := append(generateSelfSignedCertPEM(t), '\n')
	bundle = append(bundle, generateSelfSignedCertPEM(t)...)
	serveRootCA(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/cert/" {
			http.NotFound(w, r)
			return
		}
		w.Write(bundle)
	})
	dir := t.TempDir()
	caFile := filepath.Join(dir, "tls-rootca.pem")
	if err := FetchRootCA(caFile); err != nil {
		t.Fatalf("FetchRootCA: %v", err)
	}
	got, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bundle) {
		t.Errorf("pinned file differs from the served bundle")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected only the CA file in %s, found %d entries", dir, len(entries))
	}
}

// A failed fetch leaves nothing pinned, so the next attempt fetches again
// and succeeds once the endpoint serves a real certificate — rather than
// the sprout looping forever on a pinned error page.
func TestFetchRootCA_RecoversAfterFailure(t *testing.T) {
	cert := generateSelfSignedCertPEM(t)
	var ready atomic.Bool
	serveRootCA(t, func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "Jwt is missing", http.StatusUnauthorized)
			return
		}
		w.Write(cert)
	})
	caFile := filepath.Join(t.TempDir(), "tls-rootca.pem")
	if err := FetchRootCA(caFile); err == nil {
		t.Fatal("expected the first fetch to fail")
	}
	ready.Store(true)
	if err := FetchRootCA(caFile); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if got, _ := os.ReadFile(caFile); !bytes.Equal(got, cert) {
		t.Error("pinned file differs from the served certificate")
	}
}

func TestFetchRootCA_ExistingFileIsNotFetched(t *testing.T) {
	hits := serveRootCA(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(generateSelfSignedCertPEM(t))
	})
	caFile := filepath.Join(t.TempDir(), "tls-rootca.pem")
	provisioned := generateSelfSignedCertPEM(t)
	if err := os.WriteFile(caFile, provisioned, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := FetchRootCA(caFile); err != nil {
		t.Fatalf("FetchRootCA: %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("server saw %d requests, want 0", n)
	}
	if got, _ := os.ReadFile(caFile); !bytes.Equal(got, provisioned) {
		t.Error("existing CA file was modified")
	}
}

// The live failure: a sprout behind the DMZ Envoy. LoadRootCA must report
// the fetch failure and leave nothing behind for the next retry to trip on.
func TestLoadRootCA_SproutFetchFailureIsReported(t *testing.T) {
	serveRootCA(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Jwt is missing", http.StatusUnauthorized)
	})
	dir := t.TempDir()
	useSproutRootCA(t, filepath.Join(dir, "tls-rootca.pem"), true)

	if err := LoadRootCA("sprout"); !errors.Is(err, ErrRootCAFetch) {
		t.Fatalf("LoadRootCA error = %v, want ErrRootCAFetch", err)
	}
	assertNothingPinned(t, dir)
}

// A CA file that is already on disk but unusable (e.g. one pinned by the
// old, unchecked FetchRootCA) is reported, not silently replaced by a new
// trust-on-first-use fetch.
func TestLoadRootCA_UnusablePinnedFileIsKept(t *testing.T) {
	hits := serveRootCA(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(generateSelfSignedCertPEM(t))
	})
	caFile := filepath.Join(t.TempDir(), "tls-rootca.pem")
	if err := os.WriteFile(caFile, []byte("Jwt is missing"), 0o644); err != nil {
		t.Fatal(err)
	}
	useSproutRootCA(t, caFile, true)

	err := LoadRootCA("sprout")
	if !errors.Is(err, ErrCannotParseRootCA) {
		t.Fatalf("LoadRootCA error = %v, want ErrCannotParseRootCA", err)
	}
	if !strings.Contains(err.Error(), caFile) {
		t.Errorf("error should name the file to fix, got: %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("server saw %d requests, want 0", n)
	}
	if got, _ := os.ReadFile(caFile); string(got) != "Jwt is missing" {
		t.Error("existing CA file was modified")
	}
}

// A DMZ install (sproutrootcatofu: false) with no provisioned CA fails
// closed: nothing is fetched, nothing is written, and the error says what
// to provision.
func TestLoadRootCA_TOFUDisabledMissingFileFailsClosed(t *testing.T) {
	hits := serveRootCA(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(generateSelfSignedCertPEM(t))
	})
	dir := t.TempDir()
	caFile := filepath.Join(dir, "tls-rootca.pem")
	useSproutRootCA(t, caFile, false)

	err := LoadRootCA("sprout")
	if !errors.Is(err, ErrRootCANotProvisioned) {
		t.Fatalf("LoadRootCA error = %v, want ErrRootCANotProvisioned", err)
	}
	if !strings.Contains(err.Error(), caFile) || !strings.Contains(err.Error(), "sproutrootcatofu") {
		t.Errorf("error should name the file and the setting, got: %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("server saw %d requests, want 0", n)
	}
	assertNothingPinned(t, dir)
}

// With TOFU disabled, a CA provisioned out of band is loaded as is.
func TestLoadRootCA_TOFUDisabledUsesProvisionedFile(t *testing.T) {
	hits := serveRootCA(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write(generateSelfSignedCertPEM(t))
	})
	caFile := filepath.Join(t.TempDir(), "tls-rootca.pem")
	if err := os.WriteFile(caFile, generateSelfSignedCertPEM(t), 0o644); err != nil {
		t.Fatal(err)
	}
	useSproutRootCA(t, caFile, false)

	if err := LoadRootCA("sprout"); err != nil {
		t.Fatalf("LoadRootCA: %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("server saw %d requests, want 0", n)
	}
}

// sproutrootcatofu only governs the sprout; the imas CLI's missing-file
// error is unchanged.
func TestLoadRootCA_TOFUSettingIgnoredForImas(t *testing.T) {
	oldCA, oldTOFU := config.ImasRootCA, config.SproutRootCATOFU
	config.ImasRootCA = filepath.Join(t.TempDir(), "imas-rootca.pem")
	config.SproutRootCATOFU = false
	t.Cleanup(func() { config.ImasRootCA, config.SproutRootCATOFU = oldCA, oldTOFU })

	err := LoadRootCA("imas")
	if !os.IsNotExist(err) || errors.Is(err, ErrRootCANotProvisioned) {
		t.Fatalf("LoadRootCA(imas) error = %v, want a plain not-exist error", err)
	}
}
