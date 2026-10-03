// Package openbaotest gives tests that configure a real OpenBao (mounts,
// keys, policies, tokens) an admin client on the official Go client, so
// no test builds OpenBao requests or sets X-Vault-Token by hand.
package openbaotest

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	api "github.com/openbao/openbao/api/v2"
)

// Admin sends requests to one OpenBao server, as its admin token unless
// told otherwise.
type Admin struct {
	t     testing.TB
	c     *api.Client
	token string
}

// NewAdmin returns an Admin for the server at addr. It reads no BAO_* or
// VAULT_* variables.
func NewAdmin(t testing.TB, addr, token string) *Admin {
	t.Helper()
	cfg := api.NewConfig()
	cfg.Address = strings.TrimRight(addr, "/")
	cfg.MaxRetries = 0
	c, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("openbaotest: %v", err)
	}
	c.ClearToken()
	return &Admin{t: t, c: c, token: token}
}

// Call sends method /v1/<path> as token ("" means the admin token), with
// body as JSON unless nil, and returns the status and raw body whatever
// the status. It fails the test only when no response came back. Safe to
// call from t.Cleanup (it doesn't use t.Context, which is cancelled by
// then).
func (a *Admin) Call(token, method, path string, body any) (int, []byte) {
	a.t.Helper()
	if token == "" {
		token = a.token
	}
	r := a.c.NewRequest(method, "/v1/"+strings.TrimLeft(path, "/"))
	r.ClientToken = token
	if body != nil {
		if err := r.SetJSONBody(body); err != nil {
			a.t.Fatalf("openbaotest: encoding %s %s: %v", method, path, err)
		}
	}
	resp, err := a.c.RawRequestWithContext(context.Background(), r)
	if resp == nil {
		a.t.Fatalf("openbaotest: %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		a.t.Fatalf("openbaotest: %s %s: reading response: %v", method, path, err)
	}
	return resp.StatusCode, out
}

// Must is Call as the admin token, failing the test unless the status
// is 2xx.
func (a *Admin) Must(method, path string, body any) []byte {
	a.t.Helper()
	status, out := a.Call("", method, path, body)
	if status/100 != 2 {
		a.t.Fatalf("openbaotest: %s %s: status %d: %s", method, path, status, out)
	}
	return out
}

// Delete removes path as the admin token, ignoring the outcome; for
// t.Cleanup.
func (a *Admin) Delete(path string) {
	r := a.c.NewRequest(http.MethodDelete, "/v1/"+strings.TrimLeft(path, "/"))
	r.ClientToken = a.token
	if resp, _ := a.c.RawRequestWithContext(context.Background(), r); resp != nil {
		resp.Body.Close()
	}
}
