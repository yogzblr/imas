package saasapi

// Fleet release registration, the operator plane of design doc §2.5:
//
//	POST /v1/operator/fleet-releases                   register a release
//	POST /v1/operator/fleet-releases/{version}/revoke  withdraw a version
//	POST /v1/operator/tenants/{tenant_id}/purge        erase an offboarded
//	                                                   tenant's data now (S6,
//	                                                   tenant_purge.go)
//
// Every operator route is rate limited per route (operatorPlane.limiter),
// after the token check, so a caller without the token can't spend the
// operator's budget.
//
// Not tenant-facing. These routes are served only by the operator
// listener (NewOperatorServer, SAASAPI_OPERATOR_LISTEN_ADDR), never by
// NewRouter's tenant API, and they accept only the operator credential: a
// bearer token from a mounted Secret, distinct from the BFF's shared
// secret and from any end-user JWT. The intended caller is the farmer
// Helm release's post-install/post-upgrade hook Job (FU.5).
//
// Registration (P22) takes the release's packages together with its
// checksums.txt and the detached GPG signature over it
// (checksums.txt.sig). saasapi checks that checksums.txt is well formed
// with the sprout's own rules (fleetsign.ParseChecksums) and that it
// lists every package with the package's checksum, then stores the rows
// and the two files in one transaction. It never verifies the signature
// and never signs: the sprout is the only verifier, against the keyring
// shipped in its package (signing design D20). saasapi stays the only
// writer of the saas schema.
//
// FLAG FOR SECURITY REVIEW: this is the registration trust boundary.
// Whoever holds the operator token can register any well-formed release.
// What still stands between such a release and a sprout: the tenant must
// approve the version, and the sprout installs a package only if
// checksums.txt verifies against its keyring, the package's line is the
// one for the file name the sprout derives itself, and the file it
// downloads from its own configured repository has that SHA-256 (§1.8).

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"golang.org/x/mod/semver"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/yogzblr/imas/internal/fleetsign"
	log "github.com/yogzblr/imas/internal/log"
)

const (
	// maxReleaseRequestBytes bounds POST /v1/operator/fleet-releases' body:
	// checksums_txt at fleetsign.MaxChecksumsTxt, JSON-escaped, plus the
	// base64 signature and the packages.
	maxReleaseRequestBytes = 512 << 10
	// maxReleasePackages bounds one release's OS/arch entries.
	maxReleasePackages = 16

	// The operator bearer token is the whole content of a mounted Secret
	// file, surrounding whitespace trimmed.
	minBearerTokenLen  = 32
	maxBearerTokenFile = 4 << 10
)

// reChannel is a release channel name, e.g. "stable".
var reChannel = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// packageTypeOS is the OS each package type installs on: the sprout
// installs a .deb with dpkg -i, an .rpm with rpm -U and an .msi with
// msiexec (§1.8, requirement 20).
var packageTypeOS = map[string]string{"deb": "linux", "rpm": "linux", "msi": "windows"}

// operatorPlane is the operator listener's state, built once by
// NewOperatorServer.
type operatorPlane struct {
	// tokens are the operator bearer tokens accepted: the current one and,
	// during a rotation, the previous one.
	tokens [][]byte
	// limiter rate-limits each route; router installs a fresh one
	// (operatorRouteRate, operatorRouteBurst) when it is nil.
	limiter callerLimiter
}

// The operator routes' rate limit, per route and per saasapi pod: one
// request a second sustained, bursts of operatorRouteBurst. The operator
// plane's callers are a Helm hook Job and an operator at a terminal.
const (
	operatorRouteRate  rate.Limit = 1
	operatorRouteBurst int        = 10
)

// NewOperatorServer builds the operator-plane HTTPS server from cfg
// (Config's SAASAPI_OPERATOR_* settings): it reads the operator tokens
// from their Secret files and loads the listener's certificate. Start it
// with ListenAndServeTLS("", ""): the certificate is already in its
// TLSConfig.
//
// Like the tenant API, it uses the package's database (SetDB). Call it
// once at startup, only when cfg.OperatorListenAddr is set.
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
	// Separate credentials, not just separate headers: an operator token
	// that is also the BFF's secret would make the operator plane
	// reachable with a credential held for something else.
	for _, t := range p.tokens {
		for name, other := range map[string]string{
			"INTERNAL_AUTH_SECRET_CURRENT":  cfg.InternalAuthSecretCurrent,
			"INTERNAL_AUTH_SECRET_PREVIOUS": cfg.InternalAuthSecretPrevious,
		} {
			if other != "" && subtle.ConstantTimeCompare(t, []byte(other)) == 1 {
				return nil, fmt.Errorf("saasapi: the operator token must not be the same as %s", name)
			}
		}
	}
	cert, err := tls.LoadX509KeyPair(cfg.OperatorTLSCertFile, cfg.OperatorTLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("saasapi: operator plane TLS certificate: %w", err)
	}
	return &http.Server{
		Addr:              cfg.OperatorListenAddr,
		Handler:           p.handler(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      time.Minute,
		IdleTimeout:       2 * time.Minute,
	}, nil
}

// handler is router behind RejectUncleanPaths: what the operator
// listener serves.
func (p *operatorPlane) handler() http.Handler {
	return RejectUncleanPaths(p.router())
}

// router serves the operator routes and nothing else: none of NewRouter's
// tenant routes is reachable on the operator listener, and none of these
// is on the tenant API.
func (p *operatorPlane) router() *http.ServeMux {
	if p.limiter == nil {
		p.limiter = NewPerCallerLimiter(operatorRouteRate, operatorRouteBurst)
	}
	mux := http.NewServeMux()
	p.route(mux, "POST /v1/operator/fleet-releases", p.registerFleetRelease, "RegisterFleetRelease")
	p.route(mux, "POST /v1/operator/fleet-releases/{version}/revoke", p.revokeFleetRelease, "RevokeFleetRelease")
	p.route(mux, "POST /v1/operator/tenants/{tenant_id}/purge", p.purgeTenant, "PurgeTenant")
	return mux
}

func (p *operatorPlane) route(mux *http.ServeMux, pattern string, h http.HandlerFunc, name string) {
	mux.Handle(pattern, Logger(p.auth(p.rateLimit(h, name), name), name))
}

// rateLimit admits a request only while route name's bucket has a token:
// 429 rate_limited otherwise.
func (p *operatorPlane) rateLimit(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !p.limiter.allow(r.Context(), name) {
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests, slow down and retry later")
			return
		}
		inner.ServeHTTP(w, r)
	})
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
// (packaging/helm/stamp-sprout-release.sh): the per-OS/arch packages, and
// the release's checksums.txt (byte for byte) with checksums.txt.sig in
// standard padded base64.
type fleetReleaseRequest struct {
	Version          string                `json:"version"`
	Channel          string                `json:"channel"`
	MinSproutVersion string                `json:"min_sprout_version"`
	Packages         []fleetReleasePackage `json:"packages"`
	ChecksumsTxt     string                `json:"checksums_txt"`
	ChecksumsSig     string                `json:"checksums_sig"`
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
}

// releaseConflict is a registration that disagrees with what is already
// registered for its version. Its message is operator-safe.
type releaseConflict struct {
	code string
	msg  string
}

func (e *releaseConflict) Error() string { return e.msg }

// checksumsError is a checksums_txt that is malformed or doesn't match
// the packages (422). Its message is operator-safe.
type checksumsError struct {
	code string
	msg  string
}

func (e *checksumsError) Error() string { return e.msg }

// registerFleetRelease handles POST /v1/operator/fleet-releases.
//
//  1. The body is validated (validateRelease): every package's fields,
//     never normalized, plus package type and OS checks, one package per
//     OS/arch/package type, and checksums_txt and checksums_sig present
//     and within the wire contract's limits (400 invalid_release).
//  2. checksums_txt is parsed whole with the sprout's rules
//     (fleetsign.ParseChecksums): any malformed line, uppercase hash or
//     duplicate file name is 422 invalid_checksums naming the line. Every
//     package's file_name must be a line of it with checksum_sha256 as
//     its hash (422 checksums_mismatch naming the file). The signature is
//     not verified here (D20).
//  3. It is compared with the version's registered rows and checksums
//     (planRelease). Releases are immutable: an OS/arch already
//     registered with any different field, a different
//     min_sprout_version, or a different checksums_txt or checksums_sig
//     is 409 release_conflict. Packages not registered yet are to be
//     created; registered rows absent from the request are left alone. A
//     revoked version takes no new packages (409 version_revoked).
//  4. Nothing to write: 200, a no-op. This is what makes re-running the
//     Helm hook (helm upgrade, helm rollback) safe.
//  5. In one transaction, with the version's rows locked, step 3 is
//     repeated against what is there now; the new rows (with an empty
//     signature column) and, if the version has none yet, its checksums
//     row are inserted, for a 201 Created. A concurrent registration that
//     got there first with the same contents makes this one a 200 no-op
//     instead.
func (p *operatorPlane) registerFleetRelease(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxReleaseRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req fleetReleaseRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"request body must be one JSON object with version, channel, min_sprout_version, packages, checksums_txt and checksums_sig")
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
	if err := checkReleaseChecksums(req); err != nil {
		var ce *checksumsError
		if errors.As(err, &ce) {
			log.Warnf("saasapi: fleet release %s refused: %s", req.Version, ce.msg)
			writeError(w, http.StatusUnprocessableEntity, ce.code, ce.msg)
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to check checksums_txt")
		return
	}
	sums := FleetReleaseChecksums{Version: req.Version, ChecksumsTxt: req.ChecksumsTxt, ChecksumsSig: req.ChecksumsSig}

	existing, existingSums, err := loadRelease(db, req.Version, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up the release")
		return
	}
	create, needSums, err := planRelease(requested, sums, existing, existingSums)
	if writeReleaseConflict(w, req.Version, err) {
		return
	}
	if err != nil {
		log.Errorf("saasapi: planning fleet release %s: %v", req.Version, err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to check the release")
		return
	}
	if len(create) == 0 && !needSums {
		log.Infof("saasapi: fleet release %s (channel %s) already registered; nothing to do", req.Version, req.Channel)
		writeJSON(w, http.StatusOK, releaseResponse(existing, 0))
		return
	}

	now := time.Now().UTC()
	releasedAt := now
	if len(existing) > 0 {
		releasedAt = existing[0].ReleasedAt
	}
	var created int
	var wroteSums bool
	err = db.Transaction(func(tx *gorm.DB) error {
		current, currentSums, err := loadRelease(tx, req.Version, true)
		if err != nil {
			return err
		}
		toCreate, needSums, err := planRelease(requested, sums, current, currentSums)
		if err != nil {
			return err
		}
		if needSums {
			row := sums
			row.CreatedAt = now
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
		}
		for _, row := range toCreate {
			if row.ID, err = newID("fv_"); err != nil {
				return err
			}
			// The pre-P22 per-row signature column; a later migration
			// drops it.
			row.Signature, row.ReleasedAt = "", releasedAt
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
		}
		created, wroteSums = len(toCreate), needSums
		return nil
	})
	if writeReleaseConflict(w, req.Version, err) {
		return
	}
	if err != nil {
		// A concurrent registration of the same release can win the race
		// to insert: if what's there now is exactly what was asked for,
		// this request is a no-op, not a failure.
		if after, afterSums, rerr := loadRelease(db, req.Version, false); rerr == nil {
			if again, need, perr := planRelease(requested, sums, after, afterSums); perr == nil && len(again) == 0 && !need {
				writeJSON(w, http.StatusOK, releaseResponse(after, 0))
				return
			}
		}
		log.Errorf("saasapi: registering fleet release %s: %v", req.Version, err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to store the release")
		return
	}

	rows, _, err := loadRelease(db, req.Version, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "release stored, but reading it back failed")
		return
	}
	log.Infof("saasapi: fleet release %s (channel %s) registered: %d new package(s), %d in total, checksums stored: %v",
		req.Version, req.Channel, created, len(rows), wroteSums)
	status := http.StatusCreated
	if created == 0 && !wroteSums {
		status = http.StatusOK
	}
	writeJSON(w, status, releaseResponse(rows, created))
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

// validateRelease checks req's fields and returns its packages as rows.
// Nothing is normalized: a value that would have to be rewritten to be
// accepted (an uppercase checksum, surrounding space) is refused. Each
// package's fields go through fleetsign.Manifest.Validate, the sprout's
// own rules, so a row that registers is one the sprout can be served;
// file_name and checksum_sha256 are checked against checksums_txt by
// checkReleaseChecksums.
func validateRelease(req fleetReleaseRequest) ([]FleetVersion, error) {
	if !reChannel.MatchString(req.Channel) {
		return nil, errors.New("channel must be 1-32 characters of [a-z0-9_-], starting with a letter")
	}
	if len(req.Packages) == 0 || len(req.Packages) > maxReleasePackages {
		return nil, fmt.Errorf("packages must have 1 to %d entries", maxReleasePackages)
	}
	if err := validateChecksumsFields(req.ChecksumsTxt, req.ChecksumsSig); err != nil {
		return nil, err
	}
	rows := make([]FleetVersion, 0, len(req.Packages))
	seen := make(map[string]bool, len(req.Packages))
	for i, pkg := range req.Packages {
		m := fleetsign.Manifest{
			Version: req.Version, OS: pkg.OS, Arch: pkg.Arch, PackageType: pkg.PackageType,
			MinSproutVersion: req.MinSproutVersion, ChecksumsTxt: req.ChecksumsTxt, ChecksumsSig: req.ChecksumsSig,
		}
		if err := m.Validate(); err != nil {
			return nil, fmt.Errorf("packages[%d]: %w", i, err)
		}
		wantOS := packageTypeOS[pkg.PackageType] // Validate allowed only deb, rpm and msi
		switch {
		case wantOS != pkg.OS:
			return nil, fmt.Errorf("packages[%d]: a %s package is for os %s, not %s", i, pkg.PackageType, wantOS, pkg.OS)
		case !strings.HasSuffix(pkg.FileName, "."+pkg.PackageType):
			return nil, fmt.Errorf("packages[%d]: file_name must end in .%s", i, pkg.PackageType)
		}
		row := FleetVersion{
			Version:          req.Version,
			OS:               pkg.OS,
			Arch:             pkg.Arch,
			PackageType:      pkg.PackageType,
			FileName:         pkg.FileName,
			ChecksumSHA256:   pkg.ChecksumSHA256,
			MinSproutVersion: req.MinSproutVersion,
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

// validateChecksumsFields applies the wire contract's limits to
// checksums_txt (1 byte to fleetsign.MaxChecksumsTxt) and checksums_sig
// (standard padded base64 of 1 byte to fleetsign.MaxChecksumsSig).
func validateChecksumsFields(txt, sig string) error {
	switch {
	case txt == "":
		return errors.New("checksums_txt is required")
	case len(txt) > fleetsign.MaxChecksumsTxt:
		return fmt.Errorf("checksums_txt is larger than %d bytes", fleetsign.MaxChecksumsTxt)
	case sig == "":
		return errors.New("checksums_sig is required")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(sig)
	switch {
	case err != nil:
		return errors.New("checksums_sig is not standard padded base64")
	case len(raw) == 0:
		return errors.New("checksums_sig is empty")
	case len(raw) > fleetsign.MaxChecksumsSig:
		return fmt.Errorf("checksums_sig decodes to more than %d bytes", fleetsign.MaxChecksumsSig)
	}
	return nil
}

// checkReleaseChecksums parses req.ChecksumsTxt whole with the sprout's
// rules (fleetsign.ParseChecksums: every non-empty line well formed, no
// uppercase hash, no duplicate file name) and requires every package's
// file_name on a line whose hash is its checksum_sha256. A failure is a
// *checksumsError. It does not verify checksums_sig (D20).
func checkReleaseChecksums(req fleetReleaseRequest) error {
	sums, err := fleetsign.ParseChecksums([]byte(req.ChecksumsTxt))
	if err != nil {
		return &checksumsError{"invalid_checksums", "checksums_txt: " + strings.TrimPrefix(err.Error(), "fleetsign: ")}
	}
	for _, pkg := range req.Packages {
		sum, ok := sums.Sum(pkg.FileName)
		switch {
		case !ok:
			return &checksumsError{"checksums_mismatch", fmt.Sprintf("file %s is not listed in checksums_txt", pkg.FileName)}
		case sum != pkg.ChecksumSHA256:
			return &checksumsError{"checksums_mismatch", fmt.Sprintf(
				"file %s: checksum_sha256 does not match its line in checksums_txt", pkg.FileName)}
		}
	}
	return nil
}

// planRelease compares requested (one version's validated rows) and sums
// (its checksums) with existing (that version's registered rows) and
// existingSums (its registered checksums, nil if none). It returns the
// rows to create and whether the checksums row is to be inserted, or a
// *releaseConflict.
func planRelease(requested []FleetVersion, sums FleetReleaseChecksums, existing []FleetVersion,
	existingSums *FleetReleaseChecksums) ([]FleetVersion, bool, error) {
	if existingSums != nil && (existingSums.ChecksumsTxt != sums.ChecksumsTxt || existingSums.ChecksumsSig != sums.ChecksumsSig) {
		return nil, false, &releaseConflict{"release_conflict", fmt.Sprintf(
			"version %s is registered with a different checksums_txt or checksums_sig; releases are immutable, register a new version",
			sums.Version)}
	}
	byKey := make(map[string]FleetVersion, len(existing))
	revoked := false
	for _, row := range existing {
		byKey[row.releaseKey()] = row
		revoked = revoked || row.Revoked
	}
	var create []FleetVersion
	for _, want := range requested {
		if len(existing) > 0 && existing[0].MinSproutVersion != want.MinSproutVersion {
			return nil, false, &releaseConflict{"release_conflict", fmt.Sprintf(
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
			return nil, false, &releaseConflict{"release_conflict", fmt.Sprintf(
				"version %s is registered for %s with a different file_name or checksum_sha256; releases are immutable, register a new version",
				want.Version, want.releaseKey())}
		}
	}
	if revoked && len(create) > 0 {
		return nil, false, &releaseConflict{"version_revoked", fmt.Sprintf(
			"version %s has been revoked and takes no new packages; register a new version", requested[0].Version)}
	}
	// The checksums row is about to be added to a version with rows (one
	// registered before P22, or by a request this one raced): every row
	// already there must be a line of it with its own hash, or farmer
	// would serve those rows a manifest whose checksums.txt the sprout can
	// only refuse, and the checksums row can never change.
	if existingSums == nil && len(existing) > 0 {
		parsed, err := fleetsign.ParseChecksums([]byte(sums.ChecksumsTxt))
		if err != nil {
			return nil, false, err
		}
		for _, row := range existing {
			if sum, ok := parsed.Sum(row.FileName); !ok || sum != row.ChecksumSHA256 {
				return nil, false, &releaseConflict{"release_conflict", fmt.Sprintf(
					"version %s is registered for %s with file %s, which checksums_txt does not list with that checksum; releases are immutable, register a new version",
					sums.Version, row.releaseKey(), row.FileName)}
			}
		}
	}
	return create, existingSums == nil, nil
}

// loadRelease reads version's rows (loadReleaseRows) and its checksums
// row (nil if none), locking both when lock is set (inside a
// transaction).
func loadRelease(d *gorm.DB, version string, lock bool) ([]FleetVersion, *FleetReleaseChecksums, error) {
	rows, err := loadReleaseRows(d, version, lock)
	if err != nil {
		return nil, nil, err
	}
	q := d.Where("version = ?", version).Limit(1)
	if lock {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	var sums []FleetReleaseChecksums
	if err := q.Find(&sums).Error; err != nil {
		return nil, nil, err
	}
	if len(sums) == 0 {
		return rows, nil, nil
	}
	return rows, &sums[0], nil
}

// loadReleaseRows reads version's rows, ordered by OS, arch and package
// type, locking them when lock is set (inside a transaction).
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
			ChecksumSHA256: row.ChecksumSHA256,
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
