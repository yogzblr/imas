package harness

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/curve25519"

	"github.com/yogzblr/imas/internal/pki"
)

// SyntheticSprout is a made-up sprout identity: an NKey and an X25519 box
// key held by the test, never by a host. It does only step 1 of
// POST /v1/enroll (docs/design/imas-envoy-enrollment-design.md), which
// issues the identity and spends the join token. It never sends step 2,
// so farmer records no box key for it: it is an accepted sprout with no
// box key, which farmer refuses to send anything to
// (sprout_reenroll_required). That makes it the outside view of the key
// scenarios (K2, K3, T5) and of S5, without touching a real host.
type SyntheticSprout struct {
	Hostname  string
	NKeyPub   string
	SproutPub string
	kp        nkeys.KeyPair
}

// NewSyntheticSprout makes fresh keys. hostname becomes the requested
// sprout ID (lowercase letters, digits and -).
func NewSyntheticSprout(hostname string) (*SyntheticSprout, error) {
	kp, err := nkeys.CreateUser()
	if err != nil {
		return nil, err
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, err
	}
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}
	boxPub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return &SyntheticSprout{
		Hostname:  hostname,
		NKeyPub:   pub,
		SproutPub: base64.StdEncoding.EncodeToString(boxPub),
		kp:        kp,
	}, nil
}

// EnrollResult is farmer's answer to a step 1 request. The NATS User JWT
// and any gateway JWT in it are dropped, never kept or printed.
type EnrollResult struct {
	Status        int
	Error         string
	SproutID      string
	TenantID      string
	HasGatewayJWT bool
	HasBinding    bool
}

// OK reports a 200 with a sprout ID.
func (r *EnrollResult) OK() bool { return r.Status == http.StatusOK && r.SproutID != "" }

func (r *EnrollResult) String() string {
	if r.OK() {
		return fmt.Sprintf("HTTP 200 sprout %s in tenant %s", r.SproutID, r.TenantID)
	}
	return fmt.Sprintf("HTTP %d %s", r.Status, r.Error)
}

// Enroller sends enrollment requests to Envoy's /v1/enroll.
type Enroller struct {
	EnvoyURL string
	HTTP     *http.Client
	// RateLimitBudget is how long Enroll keeps retrying while Envoy's
	// enroll bucket answers 429 (default 2 minutes).
	RateLimitBudget time.Duration
}

// Enroll sends one signed step 1 request with joinToken, retrying only
// while Envoy rate-limits it. A refusal by farmer is a result (401
// enrollment_failed), not an error.
func (e *Enroller) Enroll(ctx context.Context, s *SyntheticSprout, joinToken string) (*EnrollResult, error) {
	budget := e.RateLimitBudget
	if budget <= 0 {
		budget = 2 * time.Minute
	}
	deadline := time.Now().Add(budget)
	wait := 2 * time.Second
	for {
		res, err := e.enrollOnce(ctx, s, joinToken)
		if err != nil || res.Status != http.StatusTooManyRequests || time.Now().Add(wait).After(deadline) {
			return res, err
		}
		if err := sleep(ctx, wait); err != nil {
			return res, err
		}
		if wait < 16*time.Second {
			wait *= 2
		}
	}
}

func (e *Enroller) enrollOnce(ctx context.Context, s *SyntheticSprout, joinToken string) (*EnrollResult, error) {
	ts := time.Now().Unix()
	sig, err := s.kp.Sign(pki.EnrollSigningPayload(ts, s.NKeyPub, s.Hostname, s.SproutPub, joinToken))
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]any{
		"join_token": joinToken,
		"nkey_pub":   s.NKeyPub,
		"hostname":   s.Hostname,
		"sprout_pub": s.SproutPub,
		"timestamp":  ts,
		"nkey_sig":   base64.RawURLEncoding.EncodeToString(sig),
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(e.EnvoyURL, "/")+"/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST /v1/enroll through Envoy: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		Error         string          `json:"error"`
		SproutID      string          `json:"sprout_id"`
		TenantID      string          `json:"tenant_id"`
		GatewayJWT    string          `json:"gateway_jwt"`
		EnrollBinding json.RawMessage `json:"enroll_binding"`
	}
	_ = json.Unmarshal(raw, &out)
	res := &EnrollResult{
		Status: resp.StatusCode, Error: out.Error, SproutID: out.SproutID, TenantID: out.TenantID,
		HasGatewayJWT: out.GatewayJWT != "", HasBinding: len(out.EnrollBinding) > 0 && string(out.EnrollBinding) != "null",
	}
	if res.Error == "" && resp.StatusCode != http.StatusOK {
		res.Error = strings.TrimSpace(tail(raw, 120))
	}
	return res, nil
}
