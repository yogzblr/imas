package main

// The enrolment path, for a run against a deployed bus (-servers): the
// harness holds no trust key, so its simulated sprouts get their NATS
// credentials the way a real sprout does. It mints enrolment keys for an
// existing tenant through the SaaS API (POST .../enrollment-keys, each
// good for -enroll-key-uses sprouts, one by default: a one-time key per
// sprout, as uat/enroll mints them), then enrolls each sprout through
// farmer's POST /v1/enroll with internal/pki's own client
// (pki.EnrollClient: the two signed requests, the box key proof of
// possession, a busy answer's Retry-After), each sprout with its own NKey
// and box key, made here and held only in memory. The sprouts then
// connect with the User JWT farmer issued, and over wss:// present the
// gateway JWT it issued with it. Every key it minted is revoked when the
// run ends.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/pki"
)

// saasClient calls the SaaS API as the tenant's BFF does: the shared
// X-Internal-Auth secret and the user's bearer token, both read from
// their files on every request, so a token refreshed on disk during a
// long run is picked up.
type saasClient struct {
	http       *http.Client
	base       string
	tenant     string
	secretFile string
	tokenFile  string
	// minBackoff is the first wait after a 429 (the API sends no
	// Retry-After); a variable so tests can shorten it.
	minBackoff time.Duration
}

// readOneLine reads a file holding one secret line.
func readOneLine(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	v := strings.TrimRight(string(b), "\r\n")
	if v == "" || strings.ContainsAny(v, "\r\n") {
		return "", fmt.Errorf("%s is empty or has more than one line", path)
	}
	return v, nil
}

// do sends one request and decodes a 2xx JSON answer into out (if not
// nil). Another status is an error naming the API's error code.
func (c *saasClient) do(ctx context.Context, method, path string, body, out any) (int, error) {
	secret, err := readOneLine(c.secretFile)
	if err != nil {
		return 0, fmt.Errorf("internal auth secret: %w", err)
	}
	token, err := readOneLine(c.tokenFile)
	if err != nil {
		return 0, fmt.Errorf("bearer token: %w", err)
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Internal-Auth", secret)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &e)
		return resp.StatusCode, fmt.Errorf("%s %s: HTTP %d %s %s", method, path, resp.StatusCode, e.Error, e.Message)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s %s: decoding the answer: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

func (c *saasClient) tenantPath(rest ...string) string {
	p := "/v1/tenants/" + url.PathEscape(c.tenant)
	for _, r := range rest {
		p += "/" + url.PathEscape(r)
	}
	return p
}

// checkActive fails unless the tenant is active: keys of any other
// tenant enroll nothing.
func (c *saasClient) checkActive(ctx context.Context) error {
	var st struct {
		Status string `json:"status"`
	}
	if _, err := c.do(ctx, http.MethodGet, c.tenantPath("status"), nil, &st); err != nil {
		return err
	}
	if st.Status != "active" {
		return fmt.Errorf("tenant %s is %q, not active", c.tenant, st.Status)
	}
	return nil
}

// enrollKey is one minted enrolment key. Secret is the registration_key,
// the join token; it is never logged or written.
type enrollKey struct {
	ID     string `json:"key_id"`
	Secret string `json:"registration_key"`
}

// createKey mints a key good for uses sprouts over hours, waiting out
// the API's per-tenant rate limit (429) with a doubling backoff.
func (c *saasClient) createKey(ctx context.Context, uses, hours int) (enrollKey, error) {
	backoff := max(c.minBackoff, time.Millisecond)
	for {
		var k enrollKey
		status, err := c.do(ctx, http.MethodPost, c.tenantPath("enrollment-keys"),
			map[string]int{"expires_in_hours": hours, "max_uses": uses}, &k)
		if err == nil {
			if k.ID == "" || k.Secret == "" {
				return k, errors.New("the API returned a key without key_id or registration_key")
			}
			return k, nil
		}
		if status != http.StatusTooManyRequests {
			return k, err
		}
		select {
		case <-ctx.Done():
			return k, ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 10*time.Second)
	}
}

func (c *saasClient) revokeKey(ctx context.Context, id string) error {
	_, err := c.do(ctx, http.MethodDelete, c.tenantPath("enrollment-keys", id), nil, nil)
	return err
}

// keyPool hands out join tokens, minting a new key whenever the current
// one's uses are spent, and remembers every key it minted.
type keyPool struct {
	api   *saasClient
	uses  int
	hours int

	mu      sync.Mutex
	current enrollKey
	left    int
	minted  []string
}

func (p *keyPool) take(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.left == 0 {
		k, err := p.api.createKey(ctx, p.uses, p.hours)
		if err != nil {
			return "", fmt.Errorf("minting an enrolment key: %w", err)
		}
		p.current, p.left = k, p.uses
		p.minted = append(p.minted, k.ID)
	}
	p.left--
	return p.current.Secret, nil
}

// revokeAll revokes every key the pool minted, spent or not.
func (p *keyPool) revokeAll(ctx context.Context) (int, error) {
	p.mu.Lock()
	ids := append([]string(nil), p.minted...)
	p.mu.Unlock()
	var errs []error
	for _, id := range ids {
		if err := p.api.revokeKey(ctx, id); err != nil {
			errs = append(errs, err)
		}
	}
	return len(ids), errors.Join(errs...)
}

// enrollResult is the enrolment phase of an external run.
type enrollResult struct {
	Target     int            `json:"target"`
	Enrolled   int            `json:"enrolled"`
	Failed     int            `json:"failed"`
	Reasons    map[string]int `json:"failure_reasons,omitempty"`
	Keys       int            `json:"keys_minted"`
	Seconds    float64        `json:"seconds"`
	RatePerSec float64        `json:"rate_per_sec"`
}

// enroller enrolls simulated sprouts through the real path.
type enroller struct {
	keys    *keyPool
	client  *pki.EnrollClient
	retries int
	// retryDelay is the first wait before retrying a failed sprout.
	retryDelay time.Duration
}

// enrollReason names an enrolment failure for the report.
func enrollReason(err error) string {
	switch {
	case errors.Is(err, pki.ErrFarmerBusy):
		return "farmer busy (lease held) at every try"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "run cut short"
	}
	msg := err.Error()
	for _, code := range []string{"401", "403", "429", "502", "504"} {
		if strings.Contains(msg, "HTTP "+code) {
			if code == "429" {
				return "HTTP 429 (Envoy's /v1/enroll rate limit: 20 a minute per Envoy)"
			}
			return "HTTP " + code
		}
	}
	if strings.Contains(msg, "minting an enrolment key") {
		return "minting an enrolment key failed"
	}
	return truncate(msg, 120)
}

// enrollOne makes a sprout's keys and enrolls it, retrying a failure
// with the same keys and token: farmer answers a retry of an NKey it
// already enrolled from its replay path, without spending another use.
func (e *enroller) enrollOne(ctx context.Context, hostname string) (sproutCred, error) {
	kp, err := nkeys.CreateUser()
	if err != nil {
		return sproutCred{}, err
	}
	var box [32]byte
	if _, err := rand.Read(box[:]); err != nil {
		return sproutCred{}, err
	}
	token, err := e.keys.take(ctx)
	if err != nil {
		return sproutCred{}, err
	}
	delay := e.retryDelay
	for attempt := 0; ; attempt++ {
		resp, err := e.client.Enroll(ctx, token, hostname, pki.EnrollKeys{NKey: kp, BoxPriv: &box})
		if err == nil {
			seed, err := kp.Seed()
			if err != nil {
				return sproutCred{}, err
			}
			return sproutCred{ID: resp.SproutID, JWT: resp.JWT, Seed: string(seed), Gateway: resp.GatewayJWT}, nil
		}
		if attempt >= e.retries || ctx.Err() != nil {
			return sproutCred{}, err
		}
		select {
		case <-ctx.Done():
			return sproutCred{}, err
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// enrollAll enrolls n sprouts, hostnames prefix-<i>, workers at a time.
// It returns the enrolled sprouts' credentials, in hostname order with
// the failures left out.
func (e *enroller) enrollAll(ctx context.Context, prefix string, n, workers int) ([]sproutCred, enrollResult) {
	res := enrollResult{Target: n, Reasons: map[string]int{}}
	creds := make([]sproutCred, n)
	ok := make([]bool, n)
	var mu sync.Mutex
	var done atomic.Int64
	jobs := make(chan int)
	start := time.Now()
	var wg sync.WaitGroup
	for range max(workers, 1) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				c, err := e.enrollOne(ctx, sproutID(prefix, i))
				if err != nil {
					mu.Lock()
					res.Reasons[enrollReason(err)]++
					mu.Unlock()
				} else {
					creds[i], ok[i] = c, true
				}
				if d := done.Add(1); d%1000 == 0 {
					logf("  enrolled %d of %d", d, n)
				}
			}
		}()
	}
	for i := range n {
		if ctx.Err() != nil {
			mu.Lock()
			res.Reasons["run cut short"] += n - i
			mu.Unlock()
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	var out []sproutCred
	for i := range n {
		if ok[i] {
			out = append(out, creds[i])
		}
	}
	res.Enrolled = len(out)
	res.Failed = n - len(out)
	res.Seconds = time.Since(start).Seconds()
	if res.Seconds > 0 {
		res.RatePerSec = float64(res.Enrolled) / res.Seconds
	}
	if len(res.Reasons) == 0 {
		res.Reasons = nil
	}
	return out, res
}

// tlsClient is an HTTP client trusting caFile's certificates, or the
// system roots when caFile is empty.
func tlsClient(caFile string) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificate in %s", caFile)
		}
		cfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	tr.MaxIdleConnsPerHost = 64
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}, nil
}

// enrollFleet runs the enrolment phase of an external run: it checks the
// tenant is active, enrolls o.Sprouts sprouts and returns their
// credentials, the phase's result, and a func that revokes every key it
// minted (to call when the run ends, whatever happened).
func enrollFleet(ctx context.Context, o *options) ([]sproutCred, *enrollResult, func(), error) {
	saasHTTP, err := tlsClient(o.SaasAPICA)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("-saasapi-ca: %w", err)
	}
	farmerHTTP, err := tlsClient(o.FarmerCA)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("-farmer-ca: %w", err)
	}
	api := &saasClient{
		http: saasHTTP, base: strings.TrimRight(o.SaasAPIURL, "/"), tenant: o.Tenant,
		secretFile: o.InternalAuthFile, tokenFile: o.TokenFile, minBackoff: time.Second,
	}
	if err := api.checkActive(ctx); err != nil {
		return nil, nil, nil, err
	}
	pool := &keyPool{api: api, uses: o.EnrollKeyUses, hours: o.EnrollKeyHours}
	revoke := func() {
		rctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		n, err := pool.revokeAll(rctx)
		if err != nil {
			logf("WARNING: revoking the run's enrolment keys: %v", err)
			return
		}
		if n > 0 {
			logf("revoked the %d enrolment keys this run minted", n)
		}
	}
	e := &enroller{
		keys:       pool,
		client:     &pki.EnrollClient{HTTP: farmerHTTP, FarmerURL: strings.TrimRight(o.FarmerURL, "/"), Timestamp: func() int64 { return time.Now().Unix() }},
		retries:    o.EnrollRetries,
		retryDelay: 2 * time.Second,
	}
	logf("enrolling %d sprouts in tenant %s through %s (%d at a time, keys of %d uses)", o.Sprouts, o.Tenant, o.FarmerURL, o.EnrollWorkers, o.EnrollKeyUses)
	creds, res := e.enrollAll(ctx, o.IDPrefix, o.Sprouts, o.EnrollWorkers)
	pool.mu.Lock()
	res.Keys = len(pool.minted)
	pool.mu.Unlock()
	logf("enrolled %d of %d in %.1fs (%.1f/s), %d keys minted", res.Enrolled, res.Target, res.Seconds, res.RatePerSec, res.Keys)
	return creds, &res, revoke, nil
}
