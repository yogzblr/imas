package saasapi

// Fleet release registration, the operator plane of design doc §2.5:
//
//	POST /v1/operator/fleet-releases                   register a release
//	POST /v1/operator/fleet-releases/{version}/revoke  withdraw a version
//
// Not tenant-facing. These routes are served only by the operator
// listener (NewOperatorServer, SAASAPI_OPERATOR_LISTEN_ADDR), never by
// NewRouter's tenant API, and they accept only the operator credential: a
// bearer token from a mounted Secret, distinct from the BFF's shared
// secret and from any end-user JWT. The intended caller is the farmer
// Helm release's post-install/post-upgrade hook Job (FU.5).
//
// Registration validates the release, has cmd/fleetreleaser — the only
// holder of Transit sign on imas-fleet-signing — sign each OS/arch entry,
// checks every returned signature against the read-only key set
// (fleetKeys), and only then writes the rows, in one transaction.
// saasapi stays the only writer of the saas schema, and never signs.
//
// FLAG FOR SECURITY REVIEW: this is the registration trust boundary.
// Whoever holds the operator token can have any well-formed release above
// fleetreleaser's version floor signed and registered. What still stands
// between such a release and a sprout: the tenant must approve the version,
// and the sprout downloads file_name from its own configured repository
// and installs it only if its SHA-256 matches the signed checksum (§1.8).

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"golang.org/x/mod/semver"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/yogzblr/imas/internal/fleetsign"
	log "github.com/yogzblr/imas/internal/log"
)

const (
	// maxReleaseRequestBytes bounds POST /v1/operator/fleet-releases' body.
	maxReleaseRequestBytes = 64 << 10
	// maxReleasePackages bounds one release's OS/arch entries.
	maxReleasePackages = 16

	// Bearer tokens (the operator credential, and saasapi's credential
	// for fleetreleaser) are the whole content of a mounted Secret file,
	// surrounding whitespace trimmed.
	minBearerTokenLen  = 32
	maxBearerTokenFile = 4 << 10

	// fleetReleaserTimeout bounds one signing call.
	fleetReleaserTimeout = 30 * time.Second
	// maxSignResponseBytes bounds fleetreleaser's response body.
	maxSignResponseBytes = 16 << 10
)

// reChannel is a release channel name, e.g. "stable".
var reChannel = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// packageTypeOS is the OS each package type installs on: the sprout
// installs a .deb with dpkg -i, an .rpm with rpm -U and an .msi with
// msiexec (§1.8, requirement 20).
var packageTypeOS = map[string]string{"deb": "linux", "rpm": "linux", "msi": "windows"}

// releaseSigner signs one manifest entry. *fleetReleaserClient is the real
// one; tests substitute a local key.
type releaseSigner interface {
	Sign(ctx context.Context, m fleetsign.Manifest) (signature string, err error)
}

// operatorPlane is the operator listener's state, built once by
// NewOperatorServer.
type operatorPlane struct {
	// tokens are the operator bearer tokens accepted: the current one and,
	// during a rotation, the previous one.
	tokens [][]byte
	signer releaseSigner
}

// NewOperatorServer builds the operator-plane HTTPS server from cfg
// (Config's SAASAPI_OPERATOR_* and SAASAPI_FLEETRELEASER_* settings): it
// reads the operator and fleetreleaser tokens from their Secret files,
// loads the listener's certificate and builds the fleetreleaser client.
// Start it with ListenAndServeTLS("", ""): the certificate is already in
// its TLSConfig.
//
// Like the tenant API, it uses the package's database (SetDB), and it
// needs the read-only fleet key source (SetFleetKeySource): without one,
// registration refuses with 503 rather than store a signature it can't
// check. Call it once at startup, only when cfg.OperatorListenAddr is set.
func NewOperatorServer(cfg Config) (*http.Server, error) {
	if cfg.OperatorListenAddr == "" {
		return nil, errors.New("saasapi: operator plane: SAASAPI_OPERATOR_LISTEN_ADDR is not set")
	}
	if err := cfg.validateOperator(); err != nil {
		return nil, err
	}
	p := &operatorPlane{}
	tok, err := readBearerTokenFile(cfg.OperatorTokenFile)
	if err != nil {
		return nil, fmt.Errorf("saasapi: operator token: %w", err)
	}
	p.tokens = append(p.tokens, tok)
	if cfg.OperatorTokenPreviousFile != "" {
		prev, err := readBearerTokenFile(cfg.OperatorTokenPreviousFile)
		if err != nil {
			return nil, fmt.Errorf("saasapi: previous operator token: %w", err)
		}
		p.tokens = append(p.tokens, prev)
	}
	client, err := newFleetReleaserClient(cfg.FleetReleaserURL, cfg.FleetReleaserTokenFile, cfg.FleetReleaserCAFile)
	if err != nil {
		return nil, err
	}
	// Separate credentials, not just separate headers: an operator token
	// that is also the BFF's secret or saasapi's fleetreleaser token would
	// make the operator plane reachable with a credential held for
	// something else.
	for _, t := range p.tokens {
		for name, other := range map[string]string{
			"INTERNAL_AUTH_SECRET_CURRENT":     cfg.InternalAuthSecretCurrent,
			"INTERNAL_AUTH_SECRET_PREVIOUS":    cfg.InternalAuthSecretPrevious,
			"SAASAPI_FLEETRELEASER_TOKEN_FILE": string(client.token),
		} {
			if other != "" && subtle.ConstantTimeCompare(t, []byte(other)) == 1 {
				return nil, fmt.Errorf("saasapi: the operator token must not be the same as %s", name)
			}
		}
	}
	p.signer = client
	cert, err := tls.LoadX509KeyPair(cfg.OperatorTLSCertFile, cfg.OperatorTLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("saasapi: operator plane TLS certificate: %w", err)
	}
	return &http.Server{
		Addr:              cfg.OperatorListenAddr,
		Handler:           p.router(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// One registration makes up to maxReleasePackages signing calls.
		WriteTimeout: maxReleasePackages*fleetReleaserTimeout + time.Minute,
		IdleTimeout:  2 * time.Minute,
	}, nil
}

// router serves the operator routes and nothing else: none of NewRouter's
// tenant routes is reachable on the operator listener, and none of these
// is on the tenant API.
func (p *operatorPlane) router() *http.ServeMux {
	mux := http.NewServeMux()
	p.route(mux, "POST /v1/operator/fleet-releases", p.registerFleetRelease, "RegisterFleetRelease")
	p.route(mux, "POST /v1/operator/fleet-releases/{version}/revoke", p.revokeFleetRelease, "RevokeFleetRelease")
	return mux
}

func (p *operatorPlane) route(mux *http.ServeMux, pattern string, h http.HandlerFunc, name string) {
	mux.Handle(pattern, Logger(p.auth(h, name), name))
}

// auth admits a request only with "Authorization: Bearer <t>" where t is
// one of the operator tokens, compared in constant time against every one
// (no early exit). The BFF's X-Internal-Auth secret and end-user JWTs are
// not operator credentials and are never consulted. Every failure is the
// same generic 401; the reason is logged.
func (p *operatorPlane) auth(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		authz := r.Header.Get("Authorization")
		ok := false
		if strings.HasPrefix(authz, prefix) && len(authz) > len(prefix) {
			presented := []byte(authz[len(prefix):])
			for _, tok := range p.tokens {
				if subtle.ConstantTimeCompare(presented, tok) == 1 {
					ok = true
				}
			}
		}
		if !ok {
			log.Warnf("saasapi: %s: missing or invalid operator token from %s", name, r.RemoteAddr)
			writeError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// fleetReleaseRequest is POST /v1/operator/fleet-releases' body: one
// sprout release, as the farmer chart's sprout.release carries it
// (goreleaser's checksums.txt for the per-OS/arch files).
type fleetReleaseRequest struct {
	Version          string                `json:"version"`
	Channel          string                `json:"channel"`
	MinSproutVersion string                `json:"min_sprout_version"`
	Packages         []fleetReleasePackage `json:"packages"`
}

type fleetReleasePackage struct {
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	PackageType    string `json:"package_type"`
	FileName       string `json:"file_name"`
	ChecksumSHA256 string `json:"checksum_sha256"`
}

// fleetReleaseResponse describes every registered row of the version
// after the request, not only the ones it created.
type fleetReleaseResponse struct {
	Version          string                        `json:"version"`
	MinSproutVersion string                        `json:"min_sprout_version"`
	Revoked          bool                          `json:"revoked"`
	Created          int                           `json:"created"`
	Packages         []fleetReleasePackageResponse `json:"packages"`
}

type fleetReleasePackageResponse struct {
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	PackageType    string `json:"package_type"`
	FileName       string `json:"file_name"`
	ChecksumSHA256 string `json:"checksum_sha256"`
	Signature      string `json:"signature"`
}

// releaseConflict is a registration that disagrees with what is already
// registered for its version. Its message is operator-safe.
type releaseConflict struct {
	code string
	msg  string
}

func (e *releaseConflict) Error() string { return e.msg }

// registerFleetRelease handles POST /v1/operator/fleet-releases.
//
//  1. The body is validated (validateRelease): every package with
//     fleetsign's manifest rules, never normalized, plus package type,
//     OS and file-name checks; one package per OS/arch.
//  2. It is compared with the version's registered rows (planRelease).
//     Releases are immutable: an OS/arch already registered with any
//     different field, or a different min_sprout_version, is 409
//     release_conflict. Packages not registered yet are to be created;
//     registered rows absent from the request are left alone. A revoked
//     version takes no new packages (409 version_revoked).
//  3. Nothing to create: 200, a no-op. This is what makes re-running the
//     Helm hook (helm upgrade, helm rollback) safe, and it needs neither
//     fleetreleaser nor its version floor.
//  4. Otherwise fleetreleaser signs each new package (a 4xx refusal, e.g.
//     a version at or below its floor, is 422 signing_refused; anything
//     else 502), and each signature must verify against the read-only
//     imas-fleet-signing key set.
//  5. In one transaction, with the version's rows locked, step 2 is
//     repeated against what is there now and the new rows are inserted,
//     for a 201. A concurrent registration that got there first with the
//     same contents makes this one a 200 no-op instead.
func (p *operatorPlane) registerFleetRelease(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxReleaseRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req fleetReleaseRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"request body must be one JSON object with version, channel, min_sprout_version and packages")
		return
	}
	if _, err := dec.Token(); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_request", "unexpected data after the JSON object")
		return
	}
	requested, err := validateRelease(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_release", err.Error())
		return
	}

	existing, err := loadReleaseRows(db, req.Version, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up the release")
		return
	}
	create, err := planRelease(requested, existing)
	if writeReleaseConflict(w, req.Version, err) {
		return
	}
	if len(create) == 0 {
		log.Infof("saasapi: fleet release %s (channel %s) already registered; nothing to do", req.Version, req.Channel)
		writeJSON(w, http.StatusOK, releaseResponse(existing, 0))
		return
	}

	signed, ok := p.signRelease(r.Context(), w, create)
	if !ok {
		return
	}

	releasedAt := time.Now().UTC()
	if len(existing) > 0 {
		releasedAt = existing[0].ReleasedAt
	}
	var created int
	err = db.Transaction(func(tx *gorm.DB) error {
		current, err := loadReleaseRows(tx, req.Version, true)
		if err != nil {
			return err
		}
		toCreate, err := planRelease(requested, current)
		if err != nil {
			return err
		}
		for _, row := range toCreate {
			sig, ok := signed[row.releaseKey()]
			if !ok {
				return fmt.Errorf("no signature for %s", row.releaseKey())
			}
			if row.ID, err = newID("fv_"); err != nil {
				return err
			}
			row.Signature, row.ReleasedAt = sig, releasedAt
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
		}
		created = len(toCreate)
		return nil
	})
	if writeReleaseConflict(w, req.Version, err) {
		return
	}
	if err != nil {
		// A concurrent registration of the same release can win the race
		// to insert: if what's there now is exactly what was asked for,
		// this request is a no-op, not a failure.
		if after, rerr := loadReleaseRows(db, req.Version, false); rerr == nil {
			if again, perr := planRelease(requested, after); perr == nil && len(again) == 0 {
				writeJSON(w, http.StatusOK, releaseResponse(after, 0))
				return
			}
		}
		log.Errorf("saasapi: registering fleet release %s: %v", req.Version, err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to store the release")
		return
	}

	rows, err := loadReleaseRows(db, req.Version, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "release stored, but reading it back failed")
		return
	}
	log.Infof("saasapi: fleet release %s (channel %s) registered: %d new package(s), %d in total",
		req.Version, req.Channel, created, len(rows))
	status := http.StatusCreated
	if created == 0 {
		status = http.StatusOK
	}
	writeJSON(w, status, releaseResponse(rows, created))
}

// signRelease has fleetreleaser sign every row of create and verifies each
// signature against the read-only key set. It returns the signatures by
// "os/arch", or writes the error response and returns false.
func (p *operatorPlane) signRelease(ctx context.Context, w http.ResponseWriter, create []FleetVersion) (map[string]string, bool) {
	if fleetKeys == nil {
		log.Errorf("saasapi: fleet release registration needs the read-only fleet signing key source (IMAS_FLEETSIGN_OPENBAO_*)")
		writeError(w, http.StatusServiceUnavailable, "signing_unavailable", "release signing is not configured")
		return nil, false
	}
	if p.signer == nil {
		writeError(w, http.StatusServiceUnavailable, "signing_unavailable", "release signing is not configured")
		return nil, false
	}
	ks, err := fleetKeys.KeySet(ctx)
	if err != nil {
		log.Errorf("saasapi: reading fleet signing keys: %v", err)
		writeError(w, http.StatusServiceUnavailable, "signing_unavailable", "the fleet signing key could not be read")
		return nil, false
	}
	signed := make(map[string]string, len(create))
	for _, row := range create {
		m := row.Manifest()
		sig, err := p.signer.Sign(ctx, m)
		var refused *signRefusedError
		switch {
		case errors.As(err, &refused):
			log.Warnf("saasapi: fleetreleaser refused %s %s: %s: %s", row.Version, row.releaseKey(), refused.Code, refused.Message)
			writeErrorDetails(w, http.StatusUnprocessableEntity, "signing_refused",
				fmt.Sprintf("fleetreleaser refused to sign %s %s", row.Version, row.releaseKey()),
				map[string]any{"signer_error": refused.Code, "signer_message": refused.Message})
			return nil, false
		case err != nil:
			log.Errorf("saasapi: signing %s %s: %v", row.Version, row.releaseKey(), err)
			writeError(w, http.StatusBadGateway, "signer_unavailable", "fleetreleaser could not sign the release")
			return nil, false
		}
		m.Signature = sig
		if err := ks.Verify(m); err != nil {
			log.Errorf("saasapi: fleetreleaser's signature for %s %s does not verify: %v", row.Version, row.releaseKey(), err)
			writeError(w, http.StatusBadGateway, "signer_unavailable", "fleetreleaser returned a signature that does not verify")
			return nil, false
		}
		signed[row.releaseKey()] = sig
	}
	return signed, true
}

// writeReleaseConflict writes the 409 for a *releaseConflict and reports
// whether err was one.
func writeReleaseConflict(w http.ResponseWriter, version string, err error) bool {
	var conflict *releaseConflict
	if !errors.As(err, &conflict) {
		return false
	}
	log.Warnf("saasapi: fleet release %s refused: %s", version, conflict.msg)
	writeError(w, http.StatusConflict, conflict.code, conflict.msg)
	return true
}

// validateRelease checks req and returns its packages as unsigned rows.
// Nothing is normalized: a value fleetsign would have to rewrite to accept
// (an uppercase checksum, surrounding space) is refused.
func validateRelease(req fleetReleaseRequest) ([]FleetVersion, error) {
	if !reChannel.MatchString(req.Channel) {
		return nil, errors.New("channel must be 1-32 characters of [a-z0-9_-], starting with a letter")
	}
	if len(req.Packages) == 0 || len(req.Packages) > maxReleasePackages {
		return nil, fmt.Errorf("packages must have 1 to %d entries", maxReleasePackages)
	}
	rows := make([]FleetVersion, 0, len(req.Packages))
	seen := make(map[string]bool, len(req.Packages))
	for i, pkg := range req.Packages {
		row := FleetVersion{
			Version:          req.Version,
			OS:               pkg.OS,
			Arch:             pkg.Arch,
			PackageType:      pkg.PackageType,
			FileName:         pkg.FileName,
			ChecksumSHA256:   pkg.ChecksumSHA256,
			MinSproutVersion: req.MinSproutVersion,
		}
		if err := row.Manifest().Validate(); err != nil {
			return nil, fmt.Errorf("packages[%d]: %w", i, err)
		}
		wantOS, known := packageTypeOS[pkg.PackageType]
		switch {
		case !known:
			return nil, fmt.Errorf("packages[%d]: package_type must be deb, rpm or msi", i)
		case wantOS != pkg.OS:
			return nil, fmt.Errorf("packages[%d]: a %s package is for os %s, not %s", i, pkg.PackageType, wantOS, pkg.OS)
		case !strings.HasSuffix(pkg.FileName, "."+pkg.PackageType):
			return nil, fmt.Errorf("packages[%d]: file_name must end in .%s", i, pkg.PackageType)
		}
		key := row.releaseKey()
		if seen[key] {
			return nil, fmt.Errorf("packages[%d]: more than one package for %s", i, key)
		}
		seen[key] = true
		rows = append(rows, row)
	}
	return rows, nil
}

// planRelease compares requested (one version's validated, unsigned rows)
// with existing (that version's registered rows) and returns the rows to
// create, or a *releaseConflict.
func planRelease(requested, existing []FleetVersion) ([]FleetVersion, error) {
	byKey := make(map[string]FleetVersion, len(existing))
	revoked := false
	for _, row := range existing {
		byKey[row.releaseKey()] = row
		revoked = revoked || row.Revoked
	}
	var create []FleetVersion
	for _, want := range requested {
		if len(existing) > 0 && existing[0].MinSproutVersion != want.MinSproutVersion {
			return nil, &releaseConflict{"release_conflict", fmt.Sprintf(
				"version %s is registered with min_sprout_version %s; releases are immutable, register a new version",
				want.Version, existing[0].MinSproutVersion)}
		}
		have, ok := byKey[want.releaseKey()]
		if !ok {
			create = append(create, want)
			continue
		}
		if have.FileName != want.FileName ||
			have.ChecksumSHA256 != want.ChecksumSHA256 || have.MinSproutVersion != want.MinSproutVersion {
			return nil, &releaseConflict{"release_conflict", fmt.Sprintf(
				"version %s is registered for %s with a different file_name or checksum_sha256; releases are immutable, register a new version",
				want.Version, want.releaseKey())}
		}
	}
	if revoked && len(create) > 0 {
		return nil, &releaseConflict{"version_revoked", fmt.Sprintf(
			"version %s has been revoked and takes no new packages; register a new version", requested[0].Version)}
	}
	return create, nil
}

// loadReleaseRows reads version's rows, ordered by OS and arch, locking
// them when lock is set (inside a transaction).
func loadReleaseRows(d *gorm.DB, version string, lock bool) ([]FleetVersion, error) {
	q := d.Where("version = ?", version).Order("os").Order("arch").Order("package_type")
	if lock {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var rows []FleetVersion
	err := q.Find(&rows).Error
	return rows, err
}

func releaseResponse(rows []FleetVersion, created int) fleetReleaseResponse {
	resp := fleetReleaseResponse{Created: created, Packages: make([]fleetReleasePackageResponse, 0, len(rows))}
	for _, row := range rows {
		resp.Version, resp.MinSproutVersion = row.Version, row.MinSproutVersion
		resp.Revoked = resp.Revoked || row.Revoked
		resp.Packages = append(resp.Packages, fleetReleasePackageResponse{
			OS: row.OS, Arch: row.Arch, PackageType: row.PackageType, FileName: row.FileName,
			ChecksumSHA256: row.ChecksumSHA256, Signature: row.Signature,
		})
	}
	return resp
}

// revokeResponse is POST .../{version}/revoke's 200 body.
type revokeResponse struct {
	Version  string `json:"version"`
	Revoked  bool   `json:"revoked"`
	Packages int    `json:"packages"`
	// AlreadyRevoked is true when the version was revoked before this
	// request; revoking again changes nothing.
	AlreadyRevoked bool `json:"already_revoked"`
}

// revokeFleetRelease handles POST
// /v1/operator/fleet-releases/{version}/revoke: it marks every row of the
// version revoked, in one transaction. Revocation is permanent and
// idempotent. Afterwards no manifest is served for the version (§2.6),
// no rollout of it is created or continued, and no tenant can newly
// approve it. Sprouts already running it keep it: they refuse
// downgrades. A version with no rows is 404.
func (p *operatorPlane) revokeFleetRelease(w http.ResponseWriter, r *http.Request) {
	version := r.PathValue("version")
	if len(version) > maxFleetVersionLen || !semver.IsValid(version) || semver.Canonical(version) != version {
		writeError(w, http.StatusBadRequest, "invalid_request", "version must be a canonical semver version with a leading 'v'")
		return
	}
	var resp revokeResponse
	err := db.Transaction(func(tx *gorm.DB) error {
		rows, err := loadReleaseRows(tx, version, true)
		if err != nil || len(rows) == 0 {
			return err
		}
		resp = revokeResponse{Version: version, Revoked: true, Packages: len(rows), AlreadyRevoked: true}
		for _, row := range rows {
			resp.AlreadyRevoked = resp.AlreadyRevoked && row.Revoked
		}
		return tx.Model(&FleetVersion{}).Where("version = ?", version).Update("revoked", true).Error
	})
	switch {
	case err != nil:
		log.Errorf("saasapi: revoking fleet release %s: %v", version, err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to revoke the release")
		return
	case resp.Version == "":
		writeError(w, http.StatusNotFound, "not_found", "no release is registered for this version")
		return
	}
	if !resp.AlreadyRevoked {
		log.Warnf("saasapi: fleet release %s REVOKED (%d package(s))", version, resp.Packages)
	}
	writeJSON(w, http.StatusOK, resp)
}

// readBearerTokenFile reads one bearer token from a mounted Secret file.
func readBearerTokenFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxBearerTokenFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBearerTokenFile {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxBearerTokenFile)
	}
	tok := bytes.TrimSpace(b)
	if len(tok) < minBearerTokenLen || bytes.ContainsFunc(tok, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return nil, fmt.Errorf("%s: token must be at least %d characters with no whitespace or control characters", path, minBearerTokenLen)
	}
	return tok, nil
}

// fleetReleaserClient calls cmd/fleetreleaser's POST /v1/sign over HTTPS
// with saasapi's bearer token.
type fleetReleaserClient struct {
	signURL string
	token   []byte
	http    *http.Client
}

// errSignerUnavailable: fleetreleaser couldn't be reached, or answered
// with something other than a signature or a refusal.
var errSignerUnavailable = errors.New("saasapi: fleetreleaser unavailable")

// signRefusedError is fleetreleaser declining to sign (a 4xx), with its
// error code and message.
type signRefusedError struct {
	Status  int
	Code    string
	Message string
}

func (e *signRefusedError) Error() string {
	return fmt.Sprintf("saasapi: fleetreleaser refused to sign (%d %s): %s", e.Status, e.Code, e.Message)
}

// newFleetReleaserClient builds the client. baseURL must be an https URL
// with no path, query, fragment or userinfo. caFile, if set, is the PEM
// bundle fleetreleaser's certificate chains to; otherwise the system
// roots are used.
func newFleetReleaserClient(baseURL, tokenFile, caFile string) (*fleetReleaserClient, error) {
	if err := validFleetReleaserURL(baseURL); err != nil {
		return nil, err
	}
	tok, err := readBearerTokenFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("saasapi: fleetreleaser token: %w", err)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("saasapi: reading fleetreleaser CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("saasapi: no certificates in fleetreleaser CA bundle %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &fleetReleaserClient{
		signURL: strings.TrimSuffix(baseURL, "/") + "/v1/sign",
		token:   tok,
		http: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: nil, ForceAttemptHTTP2: true},
			Timeout:   fleetReleaserTimeout,
			// The token goes to fleetreleaser and nowhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func validFleetReleaserURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return fmt.Errorf("saasapi: SAASAPI_FLEETRELEASER_URL=%q: want https://host[:port] with no path, query or credentials", s)
	}
	return nil
}

// Sign sends m's six signed fields (no signature) and returns
// fleetreleaser's signature. The caller verifies it.
func (c *fleetReleaserClient) Sign(ctx context.Context, m fleetsign.Manifest) (string, error) {
	body, err := json.Marshal(map[string]string{
		"version": m.Version, "os": m.OS, "arch": m.Arch, "file_name": m.FileName,
		"checksum_sha256": m.ChecksumSHA256, "min_sprout_version": m.MinSproutVersion,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.signURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(c.token))
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errSignerUnavailable, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSignResponseBytes))
	if err != nil {
		return "", fmt.Errorf("%w: reading response: %w", errSignerUnavailable, err)
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		var out struct {
			Signature string `json:"signature"`
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&out); err != nil || out.Signature == "" {
			return "", fmt.Errorf("%w: malformed signing response", errSignerUnavailable)
		}
		return out.Signature, nil
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnprocessableEntity:
		var out struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &out)
		return "", &signRefusedError{Status: resp.StatusCode, Code: out.Error, Message: out.Message}
	default:
		// 401 included: saasapi's own credential was refused, which is a
		// deployment fault, not something the operator's request can fix.
		return "", fmt.Errorf("%w: status %d", errSignerUnavailable, resp.StatusCode)
	}
}
