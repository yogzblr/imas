// Package sproutrelease implements `farmer register-sprout-release`: a
// one-shot run, meant for the farmer Helm chart's post-install/post-upgrade
// hook Job using farmer's own image, that registers the sprout release the
// chart carries with saasapi's operator plane
// (POST /v1/operator/fleet-releases; API design §2.5,
// docs/api/saasapi-operator-openapi.yaml). saasapi has fleetreleaser sign
// each new package and stores the rows.
//
// It reads everything from files the Job mounts: the request body the
// chart rendered, the operator bearer token, and the CA saasapi's operator
// certificate is verified against. It touches no farmer config, PKI
// directory, database, bus or OpenBao, so cmd/farmer dispatches it before
// loading any of them.
//
// Exit status, which the Job's podFailurePolicy relies on:
//
//	0  201 (registered) or 200 (already registered with these contents,
//	   the idempotent re-run of every later `helm upgrade`)
//	2  final: a 409 (the version is registered with different contents,
//	   or revoked), any other 4xx or 3xx, a certificate saasapi presents
//	   that doesn't verify, or a usage/configuration error. Retrying can't
//	   fix it, so the Job fails, and the release with it, at once.
//	1  saasapi unreachable, or 408/429/5xx, on every attempt
//
// FLAG FOR SECURITY REVIEW: this process presents the operator token,
// with which any well-formed release above fleetreleaser's floor can be
// signed. It never prints, logs or forwards it: no proxy, no redirects,
// and only the given CA is trusted.
package sproutrelease

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Command is the farmer subcommand name cmd/farmer dispatches on.
const Command = "register-sprout-release"

// Environment variables the hook Job sets. Each flag defaults to its
// variable.
const (
	EnvSaaSAPIURL     = "IMAS_SPROUT_RELEASE_SAASAPI_URL"
	EnvRequestFile    = "IMAS_SPROUT_RELEASE_REQUEST_FILE"
	EnvTokenFile      = "IMAS_SPROUT_RELEASE_TOKEN_FILE"
	EnvCAFile         = "IMAS_SPROUT_RELEASE_CA_FILE"
	EnvAttempts       = "IMAS_SPROUT_RELEASE_ATTEMPTS"
	EnvInitialBackoff = "IMAS_SPROUT_RELEASE_INITIAL_BACKOFF"
	EnvMaxBackoff     = "IMAS_SPROUT_RELEASE_MAX_BACKOFF"
	EnvRequestTimeout = "IMAS_SPROUT_RELEASE_REQUEST_TIMEOUT"
)

const (
	// RegisterPath is saasapi's operator-plane registration route.
	RegisterPath = "/v1/operator/fleet-releases"

	// The exit codes (see the package doc).
	exitOK      = 0
	exitRetries = 1
	exitFinal   = 2

	maxFileSize     = 1 << 20
	maxResponseSize = 1 << 20
	// Matches saasapi's own rule for the operator token
	// (internal/saasapi readBearerTokenFile), so a bad token is caught
	// here rather than as a 401.
	minTokenLen = 32
)

// Release is the request body: the stamped sprout release
// (packaging/helm/stamp-sprout-release.sh) plus the chart's channel. It is
// decoded only to check its shape and to report what was sent; the file's
// bytes are sent as they are.
type Release struct {
	Version          string    `json:"version"`
	Channel          string    `json:"channel"`
	MinSproutVersion string    `json:"min_sprout_version"`
	Packages         []Package `json:"packages"`
}

// Package is one OS/arch/package-type entry of a Release.
type Package struct {
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	PackageType    string `json:"package_type"`
	FileName       string `json:"file_name"`
	ChecksumSHA256 string `json:"checksum_sha256"`
}

// options is one run's configuration, from flags and the environment.
type options struct {
	saasapiURL, requestFile, tokenFile, caFile string
	attempts                                   int
	initialBackoff, maxBackoff, requestTimeout time.Duration
}

// Run parses args (everything after the subcommand name), registers the
// release and returns the process exit code. Progress and the outcome go
// to stderr; on success, saasapi's response body goes to stdout.
func Run(args []string, stdout, stderr io.Writer) int {
	o, code := parse(args, stderr)
	if code >= 0 {
		return code
	}
	return run(context.Background(), o, stdout, stderr, sleep)
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// parse returns the options, or an exit code >= 0 to return at once.
func parse(args []string, stderr io.Writer) (options, int) {
	fs := flag.NewFlagSet("farmer "+Command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.saasapiURL, "saasapi-url", os.Getenv(EnvSaaSAPIURL), "saasapi's operator listener, https://host[:port] (env "+EnvSaaSAPIURL+")")
	fs.StringVar(&o.requestFile, "request-file", os.Getenv(EnvRequestFile), "the request body: the release to register (env "+EnvRequestFile+")")
	fs.StringVar(&o.tokenFile, "token-file", os.Getenv(EnvTokenFile), "file holding the operator bearer token (env "+EnvTokenFile+")")
	fs.StringVar(&o.caFile, "ca-file", os.Getenv(EnvCAFile), "PEM CA bundle saasapi's operator certificate must verify against; the only roots trusted (env "+EnvCAFile+")")
	attempts := fs.String("attempts", envOr(EnvAttempts, "8"), "attempts for no answer, 408, 429 and 5xx (env "+EnvAttempts+")")
	initial := fs.String("initial-backoff", envOr(EnvInitialBackoff, "5s"), "wait after the first retryable failure, doubling (env "+EnvInitialBackoff+")")
	maxB := fs.String("max-backoff", envOr(EnvMaxBackoff, "60s"), "longest wait between attempts (env "+EnvMaxBackoff+")")
	timeout := fs.String("request-timeout", envOr(EnvRequestTimeout, "10m"), "deadline for one request; a registration makes up to 16 signing calls (env "+EnvRequestTimeout+")")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: farmer %s [flags]\n\n", Command)
		fmt.Fprintf(stderr, "Registers a sprout release with saasapi's operator plane (POST %s).\n\n", RegisterPath)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return o, exitFinal
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		fs.Usage()
		return o, exitFinal
	}
	var errs []string
	for _, f := range []struct{ name, v string }{
		{"-saasapi-url", o.saasapiURL}, {"-request-file", o.requestFile}, {"-token-file", o.tokenFile}, {"-ca-file", o.caFile},
	} {
		if f.v == "" {
			errs = append(errs, f.name+" is required")
		}
	}
	n, err := strconv.Atoi(*attempts)
	if err != nil || n < 1 {
		errs = append(errs, fmt.Sprintf("-attempts %q must be a whole number >= 1", *attempts))
	}
	o.attempts = n
	for _, d := range []struct {
		name, v string
		dst     *time.Duration
	}{{"-initial-backoff", *initial, &o.initialBackoff}, {"-max-backoff", *maxB, &o.maxBackoff}, {"-request-timeout", *timeout, &o.requestTimeout}} {
		v, err := time.ParseDuration(d.v)
		if err != nil || v <= 0 {
			errs = append(errs, fmt.Sprintf("%s %q must be a positive duration such as 5s", d.name, d.v))
		}
		*d.dst = v
	}
	if len(errs) > 0 {
		fmt.Fprintf(stderr, "%s: %s\n", Command, strings.Join(errs, "; "))
		return o, exitFinal
	}
	return o, -1
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func run(ctx context.Context, o options, stdout, stderr io.Writer, sleep func(context.Context, time.Duration) error) int {
	logf := func(format string, a ...any) { fmt.Fprintf(stderr, Command+": "+format+"\n", a...) }
	final := func(format string, a ...any) int { logf(format, a...); return exitFinal }

	endpoint, err := registerURL(o.saasapiURL)
	if err != nil {
		return final("%v", err)
	}
	body, rel, err := readRequest(o.requestFile)
	if err != nil {
		return final("%v", err)
	}
	token, err := readToken(o.tokenFile)
	if err != nil {
		return final("%v", err)
	}
	client, err := newClient(o.caFile)
	if err != nil {
		return final("%v", err)
	}
	logf("registering sprout release %s (min_sprout_version %s, channel %s, %d package(s)) at %s",
		rel.Version, rel.MinSproutVersion, rel.Channel, len(rel.Packages), endpoint)

	backoff := o.initialBackoff
	for attempt := 1; ; attempt++ {
		code, resp, err := post(ctx, client, endpoint, token, body, o.requestTimeout)
		var why string
		switch {
		case err != nil && isCertError(err):
			return final("saasapi's certificate does not verify against %s; not retrying: %v", o.caFile, err)
		case err != nil:
			why = fmt.Sprintf("saasapi not reachable: %v", err)
		case code == http.StatusCreated || code == http.StatusOK:
			if code == http.StatusCreated {
				logf("sprout release %s registered (%s)", rel.Version, createdSummary(resp))
			} else {
				logf("sprout release %s is already registered with these contents; nothing changed", rel.Version)
			}
			fmt.Fprintf(stdout, "%s\n", bytes.TrimSpace(resp))
			return exitOK
		case code == http.StatusConflict:
			logf("REFUSED (409): saasapi already holds version %s with different contents, or has revoked it.", rel.Version)
			logf("Releases are immutable and nothing was changed: register a new version, never re-stamp this one.")
			logf("saasapi says: %s", describeError(resp))
			logf("this chart sent:\n%s", describeRelease(rel))
			return exitFinal
		case code == http.StatusRequestTimeout || code == http.StatusTooManyRequests || code >= 500:
			why = fmt.Sprintf("HTTP %d: %s", code, describeError(resp))
		default:
			return final("REFUSED (HTTP %d), not retrying: %s", code, describeError(resp))
		}
		if attempt >= o.attempts {
			logf("giving up after %d attempt(s); last: %s", attempt, why)
			return exitRetries
		}
		logf("attempt %d/%d: %s; retrying in %s", attempt, o.attempts, why, backoff)
		if err := sleep(ctx, backoff); err != nil {
			logf("giving up: %v", err)
			return exitRetries
		}
		backoff = min(2*backoff, o.maxBackoff)
	}
}

// registerURL checks base is https://host[:port] with no path, query or
// credentials (as saasapi checks its fleetreleaser URL) and appends
// RegisterPath.
func registerURL(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("saasapi URL %q: want https://host[:port] with no path, query or credentials", base)
	}
	u.Path = RegisterPath
	return u.String(), nil
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFileSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxFileSize)
	}
	return b, nil
}

// readRequest reads the body and checks it is one JSON object of the
// request's shape, with no unknown field. Field values are saasapi's to
// validate; nothing is rewritten.
func readRequest(path string) ([]byte, Release, error) {
	var rel Release
	b, err := readFile(path)
	if err != nil {
		return nil, rel, fmt.Errorf("request: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rel); err != nil {
		return nil, rel, fmt.Errorf("request %s: %w", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, rel, fmt.Errorf("request %s: more than one JSON value", path)
	}
	if rel.Version == "" || rel.Channel == "" || rel.MinSproutVersion == "" || len(rel.Packages) == 0 {
		return nil, rel, fmt.Errorf("request %s: version, channel, min_sprout_version and at least one package are required", path)
	}
	return b, rel, nil
}

func readToken(path string) ([]byte, error) {
	b, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("operator token: %w", err)
	}
	tok := bytes.TrimSpace(b)
	if len(tok) < minTokenLen || bytes.ContainsFunc(tok, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return nil, fmt.Errorf("operator token in %s must be at least %d characters with no whitespace or control characters", path, minTokenLen)
	}
	return tok, nil
}

// newClient trusts only the CA in caFile, ignores any proxy settings and
// follows no redirect: the token goes to saasapi's operator listener and
// nowhere else.
func newClient(caFile string) (*http.Client, error) {
	pemBytes, err := readFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("CA %s holds no PEM certificate", caFile)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 10 * time.Second,
			ForceAttemptHTTP2:   true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

func post(ctx context.Context, c *http.Client, endpoint string, token, body []byte, timeout time.Duration) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, b, nil
}

// isCertError reports a certificate saasapi presented that doesn't
// verify: a configuration error, not something a retry fixes.
func isCertError(err error) bool {
	var (
		verr *tls.CertificateVerificationError
		ua   x509.UnknownAuthorityError
		he   x509.HostnameError
		ci   x509.CertificateInvalidError
	)
	return errors.As(err, &verr) || errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci)
}

// describeError renders saasapi's {"error", "message", "details"} body,
// or the body as text when it isn't one.
func describeError(b []byte) string {
	var e struct {
		Error   string          `json:"error"`
		Message string          `json:"message"`
		Details json.RawMessage `json:"details"`
	}
	if json.Unmarshal(b, &e) != nil || e.Error == "" {
		s := strings.TrimSpace(string(b))
		if s == "" {
			return "(empty body)"
		}
		return s
	}
	s := e.Error
	if e.Message != "" {
		s += ": " + e.Message
	}
	if len(e.Details) > 0 && string(e.Details) != "null" {
		s += " " + string(e.Details)
	}
	return s
}

func describeRelease(r Release) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "  version %s, min_sprout_version %s, channel %s", r.Version, r.MinSproutVersion, r.Channel)
	for _, p := range r.Packages {
		fmt.Fprintf(&sb, "\n  %s/%s/%s  %s  sha256:%s", p.OS, p.Arch, p.PackageType, p.FileName, p.ChecksumSHA256)
	}
	return sb.String()
}

func createdSummary(b []byte) string {
	var r struct {
		Created  int               `json:"created"`
		Packages []json.RawMessage `json:"packages"`
	}
	if json.Unmarshal(b, &r) != nil {
		return "response not JSON"
	}
	return fmt.Sprintf("%d new of %d package(s)", r.Created, len(r.Packages))
}
