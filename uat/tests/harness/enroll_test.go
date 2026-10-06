package harness

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/pki"
)

func TestEnrollAgainstFake(t *testing.T) {
	f, _ := fakeFleet(t)
	c := ctx(t)
	tok, _ := f.Admin(c, 1)
	key, err := f.API.MintKey(c, tok, f.TenantID(1), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSyntheticSprout("uat-synth-unit")
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.Enroll.Enroll(c, s, key.RegistrationKey)
	if err != nil || !res.OK() || res.SproutID != "uat-synth-unit" || res.TenantID != f.TenantID(1) || res.HasGatewayJWT || !res.HasBinding {
		t.Fatalf("first: %+v %v", res, err)
	}
	s2, _ := NewSyntheticSprout("uat-synth-unit2")
	res, err = f.Enroll.Enroll(c, s2, key.RegistrationKey)
	if err != nil || res.OK() || res.Status != 401 || res.Error != "enrollment_failed" {
		t.Errorf("exhausted: %+v %v", res, err)
	}
	if res.String() != "HTTP 401 enrollment_failed" {
		t.Errorf("String %q", res.String())
	}
}

// The request is signed the way farmer verifies it, and a 429 from
// Envoy's bucket is waited out.
func TestEnrollSignsAndRetries(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(429)
			_, _ = w.Write([]byte("local_rate_limited"))
			return
		}
		var req struct {
			JoinToken, NKeyPub, Hostname, SproutPub, NKeySig string
			Timestamp                                        int64
		}
		var raw map[string]any
		_ = json.NewDecoder(r.Body).Decode(&raw)
		req.JoinToken, _ = raw["join_token"].(string)
		req.NKeyPub, _ = raw["nkey_pub"].(string)
		req.Hostname, _ = raw["hostname"].(string)
		req.SproutPub, _ = raw["sprout_pub"].(string)
		req.NKeySig, _ = raw["nkey_sig"].(string)
		ts, _ := raw["timestamp"].(float64)
		req.Timestamp = int64(ts)
		kp, err := nkeys.FromPublicKey(req.NKeyPub)
		sig, err2 := base64.RawURLEncoding.DecodeString(req.NKeySig)
		pub, err3 := base64.StdEncoding.DecodeString(req.SproutPub)
		if err != nil || err2 != nil || err3 != nil || len(pub) != 32 ||
			kp.Verify(pki.EnrollSigningPayload(req.Timestamp, req.NKeyPub, req.Hostname, req.SproutPub, req.JoinToken), sig) != nil ||
			time.Since(time.Unix(req.Timestamp, 0)) > time.Minute {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"enrollment_failed"}`))
			return
		}
		_, _ = w.Write([]byte(`{"sprout_id":"h","tenant_id":"t_a","jwt":"x","gateway_jwt":"","enroll_binding":null}`))
	}))
	defer srv.Close()
	e := &Enroller{EnvoyURL: srv.URL, HTTP: srv.Client(), RateLimitBudget: 30 * time.Second}
	s, _ := NewSyntheticSprout("h")
	res, err := e.Enroll(ctx(t), s, "ek_x.secret")
	if err != nil || !res.OK() || res.HasBinding || calls.Load() != 2 {
		t.Errorf("res %+v err %v calls %d", res, err, calls.Load())
	}
}
