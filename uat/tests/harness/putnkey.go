package harness

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/pki"
)

// The legacy NKey registration of a standalone farmer (enrolment off):
// GET /pki/nkeynonce, then PUT /pki/putnkey with the NKey's signature over
// the nonce (security review L12, unit T6; internal/pki nkeynonce.go). The
// hosted stack (enrolment on, the Helm chart) registers neither route, and
// its Envoy doesn't route /pki/ to farmer (brief W1, N1).

// FarmerAnswer is a farmer HTTP answer: its status and the start of its
// body.
type FarmerAnswer struct {
	Status int
	Body   string
}

func (a FarmerAnswer) String() string {
	return fmt.Sprintf("HTTP %d %s", a.Status, strings.TrimSpace(a.Body))
}

// farmerCall sends one request to farmer's API through Envoy (EnvoyURL).
func (f *Fleet) farmerCall(ctx context.Context, method, path string, body []byte) (FarmerAnswer, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(f.Env.EnvoyURL, "/")+path, rd)
	if err != nil {
		return FarmerAnswer{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := f.Enroll.HTTP.Do(req)
	if err != nil {
		return FarmerAnswer{}, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return FarmerAnswer{Status: resp.StatusCode, Body: string(b)}, nil
}

// NKeyNonce asks for a registration nonce. The nonce is set only on a 200
// carrying one.
func (f *Fleet) NKeyNonce(ctx context.Context) (string, FarmerAnswer, error) {
	a, err := f.farmerCall(ctx, http.MethodGet, "/pki/nkeynonce", nil)
	if err != nil || a.Status != http.StatusOK {
		return "", a, err
	}
	var n pki.NKeyNonce
	if json.Unmarshal([]byte(a.Body), &n) != nil {
		return "", a, nil
	}
	return n.Nonce, a, nil
}

// PutNKey submits sub.
func (f *Fleet) PutNKey(ctx context.Context, sub pki.KeySubmission) (FarmerAnswer, error) {
	b, err := json.Marshal(sub)
	if err != nil {
		return FarmerAnswer{}, err
	}
	return f.farmerCall(ctx, http.MethodPut, "/pki/putnkey", b)
}

// NKeySubmission files nkey under sproutID over nonce, signed with
// signer's seed: a valid proof of possession when signer holds nkey,
// a forged one otherwise.
func NKeySubmission(signer nkeys.KeyPair, nkey, sproutID, nonce string) (pki.KeySubmission, error) {
	sig, err := signer.Sign(pki.NKeySubmissionPayload(nonce, sproutID, nkey))
	if err != nil {
		return pki.KeySubmission{}, err
	}
	return pki.KeySubmission{NKey: nkey, SproutID: sproutID, Nonce: nonce, Sig: base64.RawURLEncoding.EncodeToString(sig)}, nil
}
