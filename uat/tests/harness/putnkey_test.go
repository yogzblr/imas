package harness

import (
	"net/http"
	"testing"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/pki"
)

// The legacy NKey registration against the fake stack, which serves it
// with farmer's own nonce and proof checks: a proof is required, a nonce
// is spent once, and nobody files another sprout's public NKey.
func TestPutNKey(t *testing.T) {
	f, _ := fakeFleet(t)
	c := ctx(t)
	v, _ := nkeys.CreateUser()
	vpub, _ := v.PublicKey()
	a, _ := nkeys.CreateUser()
	nonce := func() string {
		n, ans, err := f.NKeyNonce(c)
		if err != nil || n == "" {
			t.Fatalf("GET /pki/nkeynonce: %s, %v", ans, err)
		}
		return n
	}
	put := func(sub pki.KeySubmission, want int) {
		t.Helper()
		got, err := f.PutNKey(c, sub)
		if err != nil || got.Status != want {
			t.Errorf("PUT %s under %s: %s, %v; want %d", sub.NKey[:6], sub.SproutID, got, err, want)
		}
	}
	sign := func(kp nkeys.KeyPair, nkey, id string) pki.KeySubmission {
		sub, err := NKeySubmission(kp, nkey, id, nonce())
		if err != nil {
			t.Fatal(err)
		}
		return sub
	}
	put(pki.KeySubmission{NKey: vpub, SproutID: "web-01", Nonce: nonce()}, http.StatusForbidden)
	ok := sign(v, vpub, "web-01")
	put(ok, http.StatusOK)
	put(ok, http.StatusForbidden)
	put(sign(a, vpub, "web-02"), http.StatusForbidden)
}
