package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"unicode"

	"golang.org/x/mod/semver"

	"github.com/yogzblr/imas/internal/fleetsign"
	log "github.com/yogzblr/imas/internal/log"
)

// releaseSigner is what the signing service needs from Transit.
// *obTransitClient is the real one; tests substitute a mock Transit.
type releaseSigner interface {
	sign(ctx context.Context, input []byte) (sig []byte, keyVersion int, err error)
	keySet(ctx context.Context) (fleetsign.KeySet, error)
}

// Caller tokens. A token is the whole content of its Secret file, with
// surrounding whitespace (the trailing newline most tools write) trimmed.
const (
	minCallerTokenLen  = 32
	maxCallerTokenFile = 4 << 10
	// maxSignRequestBytes bounds POST /v1/sign's body: one manifest entry
	// is well under 1 KiB (fleetsign's field limits).
	maxSignRequestBytes = 4 << 10
)

var errWeakCallerToken = fmt.Errorf("caller token must be at least %d characters with no whitespace or control characters", minCallerTokenLen)

// readCallerToken reads one caller token from a mounted Secret file.
func readCallerToken(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading caller token: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxCallerTokenFile+1))
	if err != nil {
		return nil, fmt.Errorf("reading caller token: %w", err)
	}
	if len(b) > maxCallerTokenFile {
		return nil, fmt.Errorf("caller token file %s is larger than %d bytes", path, maxCallerTokenFile)
	}
	tok := bytes.TrimSpace(b)
	if len(tok) < minCallerTokenLen || bytes.ContainsFunc(tok, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return nil, fmt.Errorf("%w (%s)", errWeakCallerToken, path)
	}
	return tok, nil
}

// signService is fleetreleaser's HTTP API: POST /v1/sign, and an
// unauthenticated GET /healthz for probes. It holds no state between
// requests and has no database: it signs a manifest entry and hands the
// signature back. saasapi, its only caller, stores it.
type signService struct {
	signer releaseSigner
	// tokens are the caller tokens accepted: the current one and, during a
	// rotation, the previous one. Only saasapi holds them.
	tokens [][]byte
	// floor is the version at or below which nothing is signed.
	floor string
}

// validFloor reports whether floor is a canonical semver version with a
// leading 'v' (fleetsign's rule for manifest versions).
func validFloor(floor string) bool {
	return semver.IsValid(floor) && semver.Canonical(floor) == floor
}

func (s *signService) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /v1/sign", s.requireCaller(http.HandlerFunc(s.handleSign)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	return mux
}

// requireCaller admits a request only with "Authorization: Bearer <t>"
// where t is one of s.tokens, compared in constant time against every
// configured token (no early exit, so timing doesn't say which one or how
// much matched). Every failure is the same generic 401; the reason is
// logged.
func (s *signService) requireCaller(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		authz := r.Header.Get("Authorization")
		ok := false
		if strings.HasPrefix(authz, prefix) && len(authz) > len(prefix) {
			presented := []byte(authz[len(prefix):])
			for _, tok := range s.tokens {
				if subtle.ConstantTimeCompare(presented, tok) == 1 {
					ok = true
				}
			}
		}
		if !ok {
			log.Warnf("fleetreleaser: refused %s %s from %s: missing or invalid caller token", r.Method, r.URL.Path, r.RemoteAddr)
			writeError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// signResponse is POST /v1/sign's 200 body.
type signResponse struct {
	// Signature is fleetsign.EncodeSignature's "v<key version>:<base64>"
	// over the request's fleetsign.Manifest.Message.
	Signature string `json:"signature"`
}

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// handleSign signs one manifest entry:
//
//  1. the body is decoded strictly (decodeSignRequest);
//  2. the entry is validated by internal/fleetsign (Manifest.Validate: the
//     same rules every verifier applies), never normalized;
//  3. its version must be above the configured floor;
//  4. Transit signs the canonical message (Manifest.Message), and the
//     signature is verified against the key set Transit reports before it
//     is returned, so a canonicalization or key-type mistake fails here
//     rather than on every sprout.
//
// Every signature handed out is logged with the fields it covers: this
// log is the record of everything the sole signer has signed.
func (s *signService) handleSign(w http.ResponseWriter, r *http.Request) {
	m, err := decodeSignRequest(http.MaxBytesReader(w, r.Body, maxSignRequestBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := m.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_manifest", err.Error())
		return
	}
	if semver.Compare(m.Version, s.floor) <= 0 {
		log.Warnf("fleetreleaser: refused to sign %s %s/%s: at or below the version floor %s", m.Version, m.OS, m.Arch, s.floor)
		writeError(w, http.StatusUnprocessableEntity, "version_not_above_floor",
			fmt.Sprintf("version %s is at or below the version floor %s", m.Version, s.floor))
		return
	}
	signature, keyVersion, err := signAndVerify(r.Context(), s.signer, m)
	if err != nil {
		log.Errorf("fleetreleaser: signing %s %s/%s: %v", m.Version, m.OS, m.Arch, err)
		writeError(w, http.StatusBadGateway, "signing_failed", "signing failed")
		return
	}
	log.Infof("fleetreleaser: signed version=%s os=%s arch=%s file_name=%s checksum_sha256=%s min_sprout_version=%s key_version=%d",
		m.Version, m.OS, m.Arch, m.FileName, m.ChecksumSHA256, m.MinSproutVersion, keyVersion)
	writeJSON(w, http.StatusOK, signResponse{Signature: signature})
}

// signAndVerify has Transit sign m's canonical message and checks the
// result against Transit's own key set before returning it.
func signAndVerify(ctx context.Context, s releaseSigner, m fleetsign.Manifest) (string, int, error) {
	msg, err := m.Message()
	if err != nil {
		return "", 0, err
	}
	sig, keyVersion, err := s.sign(ctx, msg)
	if err != nil {
		return "", 0, err
	}
	signature := fleetsign.EncodeSignature(keyVersion, sig)
	ks, err := s.keySet(ctx)
	if err != nil {
		return "", 0, err
	}
	m.Signature = signature
	if err := ks.Verify(m); err != nil {
		return "", 0, fmt.Errorf("fleetreleaser: Transit's signature for %s does not verify against its own key set: %w", m.Version, err)
	}
	return signature, keyVersion, nil
}

// signRequestFields maps each POST /v1/sign body key to its manifest
// field: the six signed fields of fleetsign.Manifest, spelled as its JSON
// tags. There is no signature key on the way in.
func signRequestFields(m *fleetsign.Manifest) map[string]*string {
	return map[string]*string{
		"version": &m.Version, "os": &m.OS, "arch": &m.Arch, "file_name": &m.FileName,
		"checksum_sha256": &m.ChecksumSHA256, "min_sprout_version": &m.MinSproutVersion,
	}
}

var errBadSignRequest = errors.New("body must be one JSON object with exactly the string fields version, os, arch, file_name, checksum_sha256 and min_sprout_version")

// decodeSignRequest reads POST /v1/sign's body: exactly one JSON object
// whose keys are the six manifest fields, each once, each a string, keys
// compared byte for byte (no case folding, unlike encoding/json), and
// nothing after it. Anything else is refused rather than guessed at: no
// field rides along unsigned, and what is signed is exactly what was
// sent.
func decodeSignRequest(body io.Reader) (fleetsign.Manifest, error) {
	var m fleetsign.Manifest
	dst := signRequestFields(&m)
	seen := make(map[string]bool, len(dst))
	dec := json.NewDecoder(body)
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return fleetsign.Manifest{}, errBadSignRequest
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fleetsign.Manifest{}, errBadSignRequest
		}
		key, _ := tok.(string)
		p, known := dst[key]
		if !known || seen[key] {
			return fleetsign.Manifest{}, errBadSignRequest
		}
		seen[key] = true
		tok, err = dec.Token()
		if err != nil {
			return fleetsign.Manifest{}, errBadSignRequest
		}
		v, isString := tok.(string)
		if !isString {
			return fleetsign.Manifest{}, errBadSignRequest
		}
		*p = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return fleetsign.Manifest{}, errBadSignRequest
	}
	if _, err := dec.Token(); err != io.EOF {
		return fleetsign.Manifest{}, errBadSignRequest
	}
	if len(seen) != len(dst) {
		return fleetsign.Manifest{}, errBadSignRequest
	}
	return m, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Errorf("fleetreleaser: writing response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: code, Message: message})
}
