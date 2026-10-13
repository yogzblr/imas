package harness

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFullEnrollerWaitsOutRateLimits(t *testing.T) {
	var n atomic.Int32
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		if n.Add(1) <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	fe := NewFullEnroller(srv.URL+"/", srv.Client())
	if fe.EnvoyURL != srv.URL {
		t.Errorf("the trailing slash must go: %s", fe.EnvoyURL)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/v1/enroll", bytes.NewReader([]byte("signed")))
	start := time.Now()
	resp, err := fe.HTTP.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	resp.Body.Close()
	if len(bodies) != 3 || bodies[2] != "signed" || time.Since(start) < 6*time.Second {
		t.Errorf("two 429s are waited out (2 s, 4 s) and the same body sent again: %q after %s", bodies, time.Since(start))
	}
	n.Store(-100)
	fe.RateLimitBudget = time.Second
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/v1/enroll", bytes.NewReader([]byte("x")))
	resp, err = fe.HTTP.Do(req)
	if err != nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("past the budget the 429 comes back: %v %v", resp, err)
	}
	resp.Body.Close()
}

func TestDuplicates(t *testing.T) {
	a := &Enrolment{TenantID: "t1", SproutID: "a", NKeyPub: "UA", BoxPub: "ba", JWTDigest: "ja", GatewayDigest: "ga"}
	b := &Enrolment{TenantID: "t1", SproutID: "b", NKeyPub: "UB", BoxPub: "bb", JWTDigest: "jb", GatewayDigest: "gb"}
	other := &Enrolment{TenantID: "t2", SproutID: "a", NKeyPub: "UC", BoxPub: "bc", JWTDigest: "jc", GatewayDigest: "gc"}
	if d := Duplicates([]*Enrolment{a, b, other}); len(d) != 0 {
		t.Errorf("distinct (the same sprout ID in two tenants is fine): %v", d)
	}
	c := *b
	c.SproutID, c.NKeyPub, c.BoxPub = "c", "UX", "ba"
	d := Duplicates([]*Enrolment{a, b, &c})
	if len(d) != 3 || !strings.Contains(strings.Join(d, "\n"), "the box key of sprout c is also sprout a's") ||
		!strings.Contains(strings.Join(d, "\n"), "the User JWT of sprout c is also sprout b's") {
		t.Errorf("%v", d)
	}
}
