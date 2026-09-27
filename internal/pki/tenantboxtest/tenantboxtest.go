// Package tenantboxtest is an in-process mock of the OpenBao KV v2
// endpoints internal/pki's tenantbox.go uses (GET <mount>/data/<path>,
// optionally ?version=N, and PUT <mount>/data/<path> with check-and-set),
// with per-path version history, for tests in any package that need
// tenant X25519 keypairs without an OpenBao server. The response shapes
// follow OpenBao's documented KV v2 API: data.data and data.metadata
// (version, created_time) on read, 404 for a path or version that doesn't
// exist or was deleted, 400 on a check-and-set mismatch.
//
// It deliberately doesn't import internal/pki (whose own tests use it),
// so the IMAS_TENANTBOX_OPENBAO_* variable names are repeated here.
package tenantboxtest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

const (
	Mount    = "secret"
	BasePath = "imas/tenant-x25519"
	Token    = "tenantboxtest-token"
)

// Version is one stored version of one path.
type Version struct {
	Data    map[string]string
	Created time.Time
	Deleted bool
}

// Server is a running mock. Its methods are safe to call while farmer
// code reads and writes through it.
type Server struct {
	*httptest.Server

	mu    sync.Mutex
	paths map[string][]Version // path -> versions, index i is version i+1
	// Reads and Writes count requests, for asserting on caching.
	Reads, Writes int
	// CASRejects counts writes rejected by the check-and-set guard.
	CASRejects int
}

// Start starts a mock and points the IMAS_TENANTBOX_OPENBAO_* variables
// at it with t.Setenv, so t must not be parallel. The caller still has
// to clear internal/pki's in-process key cache if an earlier test in the
// same binary populated it.
func Start(t testing.TB) *Server {
	t.Helper()
	s := &Server{paths: map[string][]Version{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	t.Setenv("IMAS_TENANTBOX_OPENBAO_ADDR", s.URL)
	t.Setenv("IMAS_TENANTBOX_OPENBAO_KV_MOUNT", Mount)
	t.Setenv("IMAS_TENANTBOX_OPENBAO_KV_PATH", BasePath)
	t.Setenv("IMAS_TENANTBOX_OPENBAO_AUTH_METHOD", "token")
	t.Setenv("IMAS_TENANTBOX_OPENBAO_TOKEN", Token)
	return s
}

// TenantPath is the KV path (under the data/ endpoint) of tenantID's
// secret.
func TenantPath(tenantID string) string { return BasePath + "/tenants/" + tenantID }

// SeedKeypair stores a fresh keypair as the next version of path, with
// extra fields merged in, and returns it.
func (s *Server) SeedKeypair(t testing.TB, path string, extra map[string]string) (pub, priv *[32]byte) {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]string{
		"pub":  base64.StdEncoding.EncodeToString(pub[:]),
		"priv": base64.StdEncoding.EncodeToString(priv[:]),
	}
	for k, v := range extra {
		data[k] = v
	}
	s.Put(path, data)
	return pub, priv
}

// Put stores data as the next version of path, created now.
func (s *Server) Put(path string, data map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paths[path] = append(s.paths[path], Version{Data: data, Created: time.Now().UTC()})
}

// Versions returns a copy of path's version history.
func (s *Server) Versions(path string) []Version {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Version(nil), s.paths[path]...)
}

// SetCreated backdates (or forward-dates) one version of path.
func (s *Server) SetCreated(path string, version int, created time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paths[path][version-1].Created = created
}

// Delete soft-deletes one version of path, as `bao kv delete -versions`.
func (s *Server) Delete(path string, version int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paths[path][version-1].Deleted = true
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Vault-Token") != Token {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, "/v1/"+Mount+"/data/")
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		s.get(w, r, path)
	case http.MethodPut, http.MethodPost:
		s.put(w, r, path)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) get(w http.ResponseWriter, r *http.Request, path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Reads++
	versions := s.paths[path]
	n := len(versions)
	if q := r.URL.Query().Get("version"); q != "" {
		v, err := strconv.Atoi(q)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n = v
	}
	if n < 1 || n > len(versions) || versions[n-1].Deleted {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
		return
	}
	v := versions[n-1]
	json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{
			"data": v.Data,
			"metadata": map[string]any{
				"version":      n,
				"created_time": v.Created.Format(time.RFC3339Nano),
			},
		},
	})
}

func (s *Server) put(w http.ResponseWriter, r *http.Request, path string) {
	var req struct {
		Options struct {
			Cas *int `json:"cas"`
		} `json:"options"`
		Data map[string]string `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Writes++
	if req.Options.Cas != nil && *req.Options.Cas != len(s.paths[path]) {
		s.CASRejects++
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"errors": []string{"check-and-set parameter did not match the current version"}})
		return
	}
	s.paths[path] = append(s.paths[path], Version{Data: req.Data, Created: time.Now().UTC()})
	json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": len(s.paths[path])}})
}
