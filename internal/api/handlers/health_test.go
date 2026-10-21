package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// withValkeyClient makes GetHealth see an installed Valkey client, which is
// all its liveness check looks at, and restores the previous state after
// the test.
func withValkeyClient(t *testing.T) {
	t.Helper()
	orig := loadValkeyPing()
	t.Cleanup(func() { setValkeyPing(orig) })
	setValkeyPing(valkeyUp)
}

func TestGetHealth_StatusOK(t *testing.T) {
	withValkeyClient(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	GetHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestGetHealth_ContentType(t *testing.T) {
	withValkeyClient(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	GetHealth(w, req)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type 'application/json', got %q", ct)
	}
}

func TestGetHealth(t *testing.T) {
	withValkeyClient(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	GetHealth(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	var body HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body.Status != "ok" {
		t.Errorf("expected status %q, got %q", "ok", body.Status)
	}

	if body.Uptime == "" {
		t.Error("expected non-empty uptime")
	}

	if body.Valkey != "ok" {
		t.Errorf("expected valkey %q, got %q", "ok", body.Valkey)
	}
}

// With no Valkey client yet (farmer is still retrying the connection),
// liveness stays 200: a restart would not connect any sooner, and GET
// /ready keeps the replica out of the Service (P30).
func TestGetHealth_NoValkeyClient(t *testing.T) {
	orig := loadValkeyPing()
	t.Cleanup(func() { setValkeyPing(orig) })
	SetReadinessValkey(nil)

	w := httptest.NewRecorder()
	GetHealth(w, httptest.NewRequest(http.MethodGet, "/health", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body HealthResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body.Status != "ok" || body.Valkey != "connecting" {
		t.Errorf("status/valkey = %q/%q, want ok/connecting", body.Status, body.Valkey)
	}
}

// A Valkey client installed after the server started (connectValkey's
// background retry) is seen by the next /health and /ready, with no
// restart; run with -race, this also checks the install is safe while
// requests are served.
func TestValkeyInstalledWhileServing(t *testing.T) {
	setReadyDeps(t, openTestPXC(t), nil, allTenantsUp)

	if code, body := getReady(t); code != http.StatusServiceUnavailable || body.Valkey != "connecting" {
		t.Fatalf("before the client: /ready = %d %+v, want 503 with valkey connecting", code, body)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 50 {
			GetHealth(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))
		}
	}()
	setValkeyPing(valkeyUp)
	<-done
	if code, body := getReady(t); code != http.StatusOK || body.Valkey != "ok" {
		t.Fatalf("after the client: /ready = %d %+v, want 200 with valkey ok", code, body)
	}
	w := httptest.NewRecorder()
	GetHealth(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	var body HealthResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || body.Valkey != "ok" {
		t.Fatalf("after the client: /health = %d %+v, want 200 with valkey ok", w.Code, body)
	}
}
