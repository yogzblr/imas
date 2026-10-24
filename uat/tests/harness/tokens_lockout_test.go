package harness

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// lockoutKeycloak is a token endpoint that grants tokens except while
// refuse is above zero, when it answers as Keycloak does a locked-out
// user and counts the refusal down.
type lockoutKeycloak struct {
	srv      *httptest.Server
	requests atomic.Int32
	refuse   atomic.Int32
	// gate, when set, holds every request until it is closed.
	gate chan struct{}
}

func newLockoutKeycloak(t *testing.T) (*lockoutKeycloak, *Tokens, *[]time.Duration) {
	t.Helper()
	kc := &lockoutKeycloak{}
	kc.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kc.requests.Add(1)
		if kc.gate != nil {
			<-kc.gate
		}
		if kc.refuse.Load() > 0 {
			kc.refuse.Add(-1)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Invalid user credentials"}`)
			return
		}
		fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":300}`, kc.requests.Load())
	}))
	t.Cleanup(kc.srv.Close)
	k, err := NewTokens(KeycloakConfig{
		Issuer: kc.srv.URL + "/realms/r", ClientID: "c",
		Tenants: map[string]KeycloakTenant{"1": {Admin: Credentials{Username: "t1-admin", Password: "pw"}}},
	}, kc.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	// A fake clock that each sleep advances.
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	var slept []time.Duration
	k.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	k.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		defer mu.Unlock()
		slept = append(slept, d)
		now = now.Add(d)
		return ctx.Err()
	}
	return kc, k, &slept
}

func TestTokensOneRequestForConcurrentCallers(t *testing.T) {
	kc, k, _ := newLockoutKeycloak(t)
	kc.gate = make(chan struct{})
	var wg sync.WaitGroup
	toks := make([]string, 8)
	errs := make([]error, 8)
	for i := range toks {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			toks[i], errs[i] = k.Tenant(ctx(t), 1, RoleAdmin)
		}(i)
	}
	// Let every caller reach Password before Keycloak answers.
	deadline := time.Now().Add(5 * time.Second)
	for kc.requests.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	close(kc.gate)
	wg.Wait()
	for i := range toks {
		if errs[i] != nil || toks[i] != toks[0] {
			t.Fatalf("caller %d: %q, %v (want %q)", i, toks[i], errs[i], toks[0])
		}
	}
	if n := kc.requests.Load(); n != 1 {
		t.Errorf("%d token requests for one user, want 1", n)
	}
}

func TestTokensWaitOutLockout(t *testing.T) {
	kc, k, slept := newLockoutKeycloak(t)
	var logged []string
	k.Logf = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	if _, err := k.Tenant(ctx(t), 1, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	k.Forget()
	kc.refuse.Store(3)
	tok, err := k.Tenant(ctx(t), 1, RoleAdmin)
	if err != nil || tok == "" {
		t.Fatalf("a known-good password should get a token once the lockout ends: %v", err)
	}
	if len(*slept) != 3 {
		t.Errorf("slept %v, want 3 waits", *slept)
	}
	if len(logged) != 2 || !strings.Contains(logged[0], "waiting up to") || !strings.Contains(logged[1], "temporary lockout") {
		t.Errorf("log lines %q", logged)
	}
}

func TestTokensLockoutGivesUp(t *testing.T) {
	kc, k, slept := newLockoutKeycloak(t)
	if _, err := k.Tenant(ctx(t), 1, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	k.Forget()
	kc.refuse.Store(1000)
	_, err := k.Tenant(ctx(t), 1, RoleAdmin)
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") || !strings.Contains(err.Error(), "user_temporarily_disabled") {
		t.Fatalf("want the lockout explained, got %v", err)
	}
	var total time.Duration
	for _, d := range *slept {
		total += d
	}
	if total < lockoutWait || total > lockoutWait+lockoutRetry {
		t.Errorf("waited %s, want about %s", total, lockoutWait)
	}
}

func TestTokensWrongPasswordFailsAtOnce(t *testing.T) {
	kc, k, slept := newLockoutKeycloak(t)
	kc.refuse.Store(1000)
	if _, err := k.Tenant(ctx(t), 1, RoleAdmin); err == nil || !isInvalidGrant(err) {
		t.Fatalf("want invalid_grant, got %v", err)
	}
	if len(*slept) != 0 || kc.requests.Load() != 1 {
		t.Errorf("a password that never worked was retried: %d requests, slept %v", kc.requests.Load(), *slept)
	}
}

func TestTokensChangedPasswordFailsAtOnce(t *testing.T) {
	kc, k, slept := newLockoutKeycloak(t)
	if _, err := k.Tenant(ctx(t), 1, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	k.Forget()
	k.cfg.Tenants["1"] = KeycloakTenant{Admin: Credentials{Username: "t1-admin", Password: "another"}}
	kc.refuse.Store(1000)
	if _, err := k.Tenant(ctx(t), 1, RoleAdmin); err == nil || !isInvalidGrant(err) {
		t.Fatalf("want invalid_grant, got %v", err)
	}
	if len(*slept) != 0 {
		t.Errorf("a password that never worked was retried (slept %v)", *slept)
	}
}
