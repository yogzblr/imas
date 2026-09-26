package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

var (
	ErrProbeMissingURL       = errors.New("probe.http requires a url")
	ErrProbeInvalidTimeout   = errors.New("probe.http timeout must be a valid duration")
	ErrProbeUnexpectedStatus = errors.New("probe.http received an unexpected status code")
	ErrProbeBodyMismatch     = errors.New("probe.http response body did not contain the expected text")
	ErrProbeHeaderMismatch   = errors.New("probe.http response header did not match the expected value")
)

// maxCapturedBodyBytes bounds how much of a response body is copied into a
// step's notes (and therefore is what a `register` on this step captures).
// Probes are meant to check availability/shape, not stream large payloads.
const maxCapturedBodyBytes = 8192

var httpMethodProps = ingredients.MethodPropsSet{
	ingredients.MethodProps{Key: "url", Type: "string", IsReq: true, Description: "URL to request"},
	ingredients.MethodProps{Key: "method", Type: "string", IsReq: false, Description: "HTTP method, default GET"},
	ingredients.MethodProps{Key: "body", Type: "string", IsReq: false, Description: "request body"},
	ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false, Description: "request timeout, e.g. 10s (default 10s)"},
	ingredients.MethodProps{Key: "insecure_skip_verify", Type: "bool", IsReq: false, Description: "skip TLS certificate verification"},
	ingredients.MethodProps{Key: "expect_body_contains", Type: "string", IsReq: false, Description: "substring the response body must contain"},
}

// newHTTPClient returns a client scoped to a single probe request.
// insecure disables TLS certificate verification -- default false, and only
// ever set by an explicit recipe property, never implicitly.
func newHTTPClient(insecure bool) *http.Client {
	if !insecure {
		return &http.Client{}
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // explicit opt-in via insecure_skip_verify
		},
	}
}

func stringMap(v interface{}) map[string]string {
	out := map[string]string{}
	m, ok := v.(map[string]interface{})
	if !ok {
		return out
	}
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		} else {
			out[k] = fmt.Sprintf("%v", val)
		}
	}
	return out
}

// expectedStatuses reads "expect_status", accepting either a single int (or
// numeric string) or a list of them. An empty/absent value means "any 2xx".
func parseStatus(x interface{}) (int, error) {
	if s, ok := x.(string); ok {
		return strconv.Atoi(s)
	}
	return toInt(x)
}

func expectedStatuses(v interface{}) ([]int, error) {
	switch t := v.(type) {
	case nil:
		return nil, nil
	case []interface{}:
		out := make([]int, 0, len(t))
		for _, item := range t {
			n, err := parseStatus(item)
			if err != nil {
				return nil, err
			}
			out = append(out, n)
		}
		return out, nil
	default:
		n, err := parseStatus(t)
		if err != nil {
			return nil, err
		}
		return []int{n}, nil
	}
}

func (p Probe) probeHTTP(ctx context.Context) (cook.Result, error) {
	url, ok := p.params["url"].(string)
	if !ok || url == "" {
		return cook.Result{Succeeded: false, Failed: true}, ErrProbeMissingURL
	}

	method, _ := p.params["method"].(string)
	if method == "" {
		method = http.MethodGet
	}
	method = strings.ToUpper(method)

	var bodyReader io.Reader
	if body, ok := p.params["body"].(string); ok && body != "" {
		bodyReader = strings.NewReader(body)
	}

	timeout := 10 * time.Second
	if ts, ok := p.params["timeout"].(string); ok && ts != "" {
		d, err := time.ParseDuration(ts)
		if err != nil {
			return cook.Result{Succeeded: false, Failed: true}, errors.Join(ErrProbeInvalidTimeout, err)
		}
		timeout = d
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, method, url, bodyReader)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true}, err
	}
	for k, v := range stringMap(p.params["headers"]) {
		req.Header.Set(k, v)
	}

	insecure, _ := p.params["insecure_skip_verify"].(bool)
	client := newHTTPClient(insecure)

	resp, err := client.Do(req)
	if err != nil {
		return cook.Result{
			Succeeded: false, Failed: true,
			Notes: []fmt.Stringer{cook.Snprintf("request to %s failed: %v", url, err)},
		}, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, maxCapturedBodyBytes)
	rawBody, readErr := io.ReadAll(limited)
	if readErr != nil {
		return cook.Result{Succeeded: false, Failed: true}, readErr
	}
	respBody := string(rawBody)

	notes := []fmt.Stringer{
		cook.Snprintf("%s %s -> %d", method, url, resp.StatusCode),
		cook.Snprintf("%s", respBody),
	}

	wantStatuses, err := expectedStatuses(p.params["expect_status"])
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Notes: notes}, err
	}
	statusOK := false
	if len(wantStatuses) == 0 {
		statusOK = resp.StatusCode >= 200 && resp.StatusCode < 300
	} else {
		for _, s := range wantStatuses {
			if resp.StatusCode == s {
				statusOK = true
				break
			}
		}
	}
	if !statusOK {
		return cook.Result{Succeeded: false, Failed: true, Notes: notes},
			fmt.Errorf("%w: got %d, want %v", ErrProbeUnexpectedStatus, resp.StatusCode, wantStatuses)
	}

	if want, ok := p.params["expect_body_contains"].(string); ok && want != "" {
		if !strings.Contains(respBody, want) {
			return cook.Result{Succeeded: false, Failed: true, Notes: notes}, ErrProbeBodyMismatch
		}
	}

	for k, want := range stringMap(p.params["expect_header"]) {
		if got := resp.Header.Get(k); got != want {
			return cook.Result{Succeeded: false, Failed: true, Notes: notes},
				fmt.Errorf("%w: header %s = %q, want %q", ErrProbeHeaderMismatch, k, got, want)
		}
	}

	return cook.Result{Succeeded: true, Failed: false, Changed: false, Notes: notes}, nil
}
