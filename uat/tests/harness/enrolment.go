package harness

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/curve25519"

	"github.com/yogzblr/imas/internal/pki"
)

// Enrolment is one sprout the ha tier enrolled in full: both requests of
// POST /v1/enroll through Envoy, as a sprout makes them (pki.EnrollClient),
// so farmer records its box key and issues its User JWT and gateway JWT.
// Unlike a SyntheticSprout it is a complete sprout identity: its User JWT
// and NKey seed authenticate on the bus (BusConn). The tokens are held in
// memory for that and compared by digest; neither is ever printed.
type Enrolment struct {
	Hostname  string
	SproutID  string
	TenantID  string
	NKeyPub   string
	BoxPub    string
	JoinToken string
	// JWTDigest and GatewayDigest are the SHA-256 of the User JWT and the
	// gateway JWT, hex: what duplicate checks compare.
	JWTDigest     string
	GatewayDigest string
	Start, End    time.Time

	kp      nkeys.KeyPair
	boxPriv *[32]byte
	userJWT string
}

// UserJWT is the sprout's NATS User JWT (a credential: never print it).
func (e *Enrolment) UserJWT() string { return e.userJWT }

// Seed is the sprout's NKey seed (a credential: never print it).
func (e *Enrolment) Seed() ([]byte, error) { return e.kp.Seed() }

// FullEnroller enrols complete sprouts through Envoy's /v1/enroll with the
// sprout's own client (pki.EnrollClient): step 1 issues the identity,
// step 2 proves the box key and gets the gateway JWT. Envoy's 429 on
// /v1/enroll (20 requests per 60 s per Envoy) is waited out in the
// transport, so the rate limit is never a failure; anything else is.
type FullEnroller struct {
	EnvoyURL string
	HTTP     *http.Client
	// RateLimitBudget bounds the 429 waits of one request (default 3
	// minutes).
	RateLimitBudget time.Duration
}

// NewFullEnroller returns an enroller over a copy of hc whose transport
// waits out 429s.
func NewFullEnroller(envoyURL string, hc *http.Client) *FullEnroller {
	fe := &FullEnroller{EnvoyURL: strings.TrimRight(envoyURL, "/"), RateLimitBudget: 3 * time.Minute}
	c := *hc
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c.Transport = &waitRateLimit{next: base, budget: func() time.Duration { return fe.RateLimitBudget }}
	fe.HTTP = &c
	return fe
}

// waitRateLimit retries a request answered 429, waiting 2 s, then
// doubling up to 16 s, within a budget. Safe for /v1/enroll: a 429 is
// Envoy's, so farmer never saw (or claimed) the signed request.
type waitRateLimit struct {
	next   http.RoundTripper
	budget func() time.Duration
}

func (w *waitRateLimit) RoundTrip(req *http.Request) (*http.Response, error) {
	deadline := time.Now().Add(w.budget())
	wait := 2 * time.Second
	for {
		resp, err := w.next.RoundTrip(req)
		if err != nil || resp.StatusCode != http.StatusTooManyRequests || req.GetBody == nil || time.Now().Add(wait).After(deadline) {
			return resp, err
		}
		resp.Body.Close()
		if err := sleep(req.Context(), wait); err != nil {
			return nil, err
		}
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		req = req.Clone(req.Context())
		req.Body = body
		if wait < 16*time.Second {
			wait *= 2
		}
	}
}

// NewEnrolment makes fresh keys for a sprout asking for hostname as its ID.
func NewEnrolment(hostname, joinToken string) (*Enrolment, error) {
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
	e := &Enrolment{Hostname: hostname, JoinToken: joinToken, NKeyPub: pub, kp: kp, boxPriv: &priv}
	e.BoxPub = base64.StdEncoding.EncodeToString(boxPub)
	return e, nil
}

// Enrol enrols e (both requests) and records its identity.
func (fe *FullEnroller) Enrol(ctx context.Context, e *Enrolment) error {
	e.Start = time.Now()
	resp, err := fe.client().Enroll(ctx, e.JoinToken, e.Hostname, pki.EnrollKeys{NKey: e.kp, BoxPriv: e.boxPriv})
	e.End = time.Now()
	if err != nil {
		return fmt.Errorf("enrolling %s: %w", e.Hostname, err)
	}
	e.SproutID, e.TenantID = resp.SproutID, resp.TenantID
	e.userJWT = resp.JWT
	e.JWTDigest = digest(resp.JWT)
	e.GatewayDigest = digest(resp.GatewayJWT)
	return nil
}

// Replay enrols e's keys again with its join token: farmer answers from
// its replay path (the NKey is enrolled, its box key on record), spending
// no token. It must name the same sprout and tenant and hand back the
// same User JWT (mint-or-reuse, design T6): a different one is a
// duplicate JWT minted by another replica. The second request re-asserts
// the box key, which farmer accepts only when it is the one on record.
func (fe *FullEnroller) Replay(ctx context.Context, e *Enrolment) error {
	resp, err := fe.client().Enroll(ctx, e.JoinToken, e.Hostname, pki.EnrollKeys{NKey: e.kp, BoxPriv: e.boxPriv})
	if err != nil {
		return fmt.Errorf("enrolling sprout %s again with the same keys: %w", e.SproutID, err)
	}
	switch {
	case resp.SproutID != e.SproutID || resp.TenantID != e.TenantID:
		return fmt.Errorf("enrolling sprout %s again named sprout %s in tenant %s", e.SproutID, resp.SproutID, resp.TenantID)
	case digest(resp.JWT) != e.JWTDigest:
		return fmt.Errorf("sprout %s got a different User JWT on its second enrolment: a second JWT was minted for it", e.SproutID)
	}
	return nil
}

func (fe *FullEnroller) client() *pki.EnrollClient {
	return &pki.EnrollClient{HTTP: fe.HTTP, FarmerURL: fe.EnvoyURL}
}

// Duplicates checks that the enrolments name distinct sprouts, NKeys,
// box keys, User JWTs and gateway JWTs, and describes every clash.
func Duplicates(list []*Enrolment) []string {
	var out []string
	check := func(what string, key func(*Enrolment) string) {
		seen := map[string]string{}
		for _, e := range list {
			k := key(e)
			if k == "" {
				continue
			}
			tk := e.TenantID + "/" + k
			if prev, ok := seen[tk]; ok {
				out = append(out, fmt.Sprintf("%s of sprout %s is also sprout %s's", what, e.SproutID, prev))
				continue
			}
			seen[tk] = e.SproutID
		}
	}
	check("the sprout ID", func(e *Enrolment) string { return e.SproutID })
	check("the NKey", func(e *Enrolment) string { return e.NKeyPub })
	check("the box key", func(e *Enrolment) string { return e.BoxPub })
	check("the User JWT", func(e *Enrolment) string { return e.JWTDigest })
	check("the gateway JWT", func(e *Enrolment) string { return e.GatewayDigest })
	sort.Strings(out)
	return out
}

// ReplayAll replays every enrolment one after another and returns the
// failures.
func (fe *FullEnroller) ReplayAll(ctx context.Context, list []*Enrolment) []string {
	var out []string
	for _, e := range list {
		if err := fe.Replay(ctx, e); err != nil {
			out = append(out, err.Error())
		}
		if ctx.Err() != nil {
			out = append(out, ctx.Err().Error())
			break
		}
	}
	return out
}

// ErrNoEnrolments is returned when a check has nothing to look at.
var ErrNoEnrolments = errors.New("no enrolment succeeded, so nothing could be checked")

func digest(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
