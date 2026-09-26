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
	orig := valkeyPing
	t.Cleanup(func() { valkeyPing = orig })
	valkeyPing = valkeyUp
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

// With no Valkey client (initValkeyClient failed at boot and never
// retries), liveness fails so kubelet restarts the pod.
func TestGetHealth_NoValkeyClient(t *testing.T) {
	orig := valkeyPing
	t.Cleanup(func() { valkeyPing = orig })
	SetReadinessValkey(nil)

	w := httptest.NewRecorder()
	GetHealth(w, httptest.NewRequest(http.MethodGet, "/health", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	var body HealthResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if body.Status != "unhealthy" || body.Valkey != "not configured" {
		t.Errorf("status/valkey = %q/%q, want unhealthy/not configured", body.Status, body.Valkey)
	}
}
