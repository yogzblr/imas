package pki

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	log "github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/internal/config"
)

type PubKeyType int

const (
	SproutPubNKey PubKeyType = iota
	FarmerPubNKey
	CliPubNKey
)

// sproutMatcher is the shape of a sprout ID: lowercase letters, digits,
// '-' and '_', starting with a letter or digit. No '.': a sprout ID is
// one NATS subject token. Every grant and subscription that names a
// sprout puts its ID in one token position (imas.sprouts.<id>.>,
// imas.sprouts.announce.<id>, imas.cook.<id>.>, imas.logs.sprouts.<id>.>,
// and the farmer side's imas.sprouts.*.facts, imas.sprouts.*.boxkey.pub,
// imas.cook.*.*), so a dot would make sprout "web01"'s grants cover
// "web01.example.com"'s subjects, and the single-token wildcards would
// never match a dotted ID at all (security review 2026-10, M4).
var sproutMatcher = regexp.MustCompile(`^[0-9a-z][-0-9_a-z]*$`)

// reservedSproutIDs are subject tokens that sit where a sprout ID does in
// some subject, so a sprout holding one as its ID would be granted
// another subject tree: imas.sprouts.announce.<id> is every sprout's
// startup announcement, so a sprout named "announce" would subscribe to
// all of them through its imas.sprouts.<id>.> grant. Nothing else under
// imas.sprouts., imas.cook. or imas.logs.sprouts. puts a fixed token in
// the ID's position today; add any new one here.
var reservedSproutIDs = map[string]bool{
	"announce": true,
}

// maxSproutIDLen bounds a sprout ID (and the pki_nkeys.sprout_id column).
const maxSproutIDLen = 253

// SetupPKIFarmer ensures the farmer's PKI directory exists. Sprout NKey
// lifecycle state itself now lives in PXC (see store.go) — this directory
// is still needed for the nats-auth trust-chain material (jwtauth.go) and
// the TLS certificate files (config.CertFile/KeyFile) that live under it.
func SetupPKIFarmer() {
	FarmerPKI := config.FarmerPKI
	_, err := os.Stat(FarmerPKI)
	if os.IsNotExist(err) {
		err = os.MkdirAll(FarmerPKI, os.ModePerm)
		if err != nil {
			if os.IsPermission(err) {
				log.Fatalf("insufficient permissions to create PKI directory %s: %v", FarmerPKI, err)
			}
			log.Fatalf("failed to create PKI directory %s: %v", FarmerPKI, err)
		}
	}
}

func SetupPKISprout() {
	SproutPKI := config.SproutPKI
	_, err := os.Stat(SproutPKI)
	if err == nil {
		return
	}
	if os.IsNotExist(err) {
		err = os.MkdirAll(SproutPKI, os.ModePerm)
		if err != nil {
			log.Panicf("failed to create sprout PKI directory: %v", err)
		}
	} else {

		log.Panicf("unexpected error checking sprout PKI directory: %v", err)
	}
}

// Rules on sprout IDs (IsValidSproutID): unique per tenant; lowercase
// letters, digits, '-' and '_', starting with a letter or digit; at most
// maxSproutIDLen characters; no '.' and none of reservedSproutIDs. If
// several sprouts in a tenant claim the same ID, the first one gets it and
// later ones get <id>_<n> (resolveEnrollSproutID). NormalizeSproutID turns
// a hostname into this shape.

// NormalizeSproutID maps a hostname to sprout ID form: lowercased, '_' and
// '.' turned into '-', and leading and trailing '-' removed, so
// "Web01.Example.COM." becomes "web01-example-com". The result may still
// be invalid (empty, reserved, too long or containing other characters);
// callers check it with IsValidSproutID.
func NormalizeSproutID(hostname string) string {
	id := strings.ToLower(hostname)
	id = strings.NewReplacer("_", "-", ".", "-").Replace(id)
	return strings.Trim(id, "-")
}

func createSproutID() string {
	id, err := os.Hostname()
	if err != nil {
		// Fall back to "unknown" if hostname cannot be determined
		log.Errorf("failed to get hostname for sprout ID: %v", err)
		id = "unknown"
	}
	return NormalizeSproutID(id)
}

// IsValidSproutID reports whether id is a well-formed sprout ID: see the
// rules above. FLAG FOR SECURITY REVIEW: this is what keeps one sprout's
// minted grants (jwtusers.go's sproutPermissions) from covering another
// sprout's subjects.
func IsValidSproutID(id string) bool {
	if len(id) > maxSproutIDLen {
		return false
	}
	if !sproutMatcher.MatchString(id) {
		return false
	}
	return !reservedSproutIDs[id]
}

// reloadNKeysFor syncs and pushes tenantID's NATS Account after an
// Accept/Deny/Reject/Unaccept/Delete call. tenantID's own Account
// (ReloadNKeysForTenant) is used for every tenant except the legacy
// current-tenant seam (currentTenantID()), which instead uses the
// original, flat single-tenant path (ReloadNKeys/syncNatsAuth,
// jwtusers.go's sproutJWTPath) — that path predates tenant.go's
// tenants/<id>/ layout and is what GetSproutUserJWT (jwtusers.go) and
// every other legacy caller still reads from. Treating the legacy tenant
// as just another ID for ReloadNKeysForTenant would silently start
// provisioning a *second*, separate Account under tenants/<id>/ for it,
// orphaning every sprout the flat legacy path already manages. See
// docs/design/imas-tenant-context-threading.md.
func reloadNKeysFor(tenantID string) error {
	if tenantID == currentTenantID() {
		return ReloadNKeys()
	}
	return ReloadNKeysForTenant(tenantID)
}

// AcceptNKey moves sproutID from unaccepted/denied/rejected into accepted
// within tenantID, syncing and pushing that tenant's own NATS Account
// afterward (reloadNKeysFor) — not unconditionally the legacy
// current-tenant seam, so accepting a sprout under a
// dynamically-provisioned tenant reloads the right Account. See
// docs/design/imas-tenant-context-threading.md.
//
// Accepting <base>_<n> replaces <base>: the host that took the suffixed ID
// because <base> was in use becomes <base>. FLAG FOR SECURITY REVIEW
// (security review 2026-10, H1): the replaced host is retired exactly as
// DeleteNKey retires one (retireSproutTx), in the same transaction as the
// rename, so its NKey is revoked on the Account and its box keys stop
// sealing and opening. The new host's box keys move from <base>_<n> to
// <base> with it. An NKey on the tenant's revoked list is never accepted
// again (ErrNKeyRevoked).
func AcceptNKey(tenantID, id string) error {
	defer func() {
		if err := reloadNKeysFor(tenantID); err != nil {
			log.Errorf("failed to reload NATS auth for accepted sprout %s in tenant %s: %v", id, tenantID, err)
		}
	}()
	base := strings.SplitN(id, "_", 2)[0]
	if !IsValidSproutID(base) {
		return ErrSproutIDInvalid
	}
	row, err := findNKeyRowInTenant(tenantID, id)
	if err != nil {
		return err
	}
	if id == base && row.State == stateAccepted {
		return ErrAlreadyAccepted
	}
	revoked, err := isNKeyRevoked(tenantID, row.NKey)
	if err != nil {
		return err
	}
	if revoked {
		return ErrNKeyRevoked
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if id != base {
			if _, err := retireSproutTx(tx, tenantID, base, row.NKey); err != nil {
				return err
			}
			if err := moveSproutBoxKeysTx(tx, tenantID, id, base); err != nil {
				return err
			}
		}
		if err := tx.Where("tenant_id = ? AND sprout_id = ?", tenantID, id).Delete(&nkeyRow{}).Error; err != nil {
			return err
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "sprout_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"nkey", "state"}),
		}).Create(&nkeyRow{TenantID: tenantID, SproutID: base, NKey: row.NKey, State: stateAccepted}).Error
	})
}

// DeleteNKey removes sprout id from tenantID and ends its credentials.
// FLAG FOR SECURITY REVIEW (security review 2026-10, H1): deleting only
// the pki_nkeys row, as this used to, left the sprout's User JWT valid
// (User JWTs carry no exp, and the Account's revocations were rebuilt only
// from rows still on record) and its box key active. Now, in one
// transaction (retireSproutTx), its NKey goes on the tenant's revoked
// list, which every Account rebuild applies (applyRevokedNKeys), and every
// one of its box keys is revoked. The deferred reload then pushes the
// Account JWT carrying the revocation, which closes a live connection and
// refuses the JWT on reconnect.
//
// The sprout ID itself is free again: a host can enrol under it, but only
// with an NKey that isn't revoked, and it gets a fresh box key.
func DeleteNKey(tenantID, id string) error {
	defer func() {
		if err := reloadNKeysFor(tenantID); err != nil {
			log.Errorf("failed to reload NATS auth for deleted sprout %s in tenant %s: %v", id, tenantID, err)
		}
	}()
	if !IsValidSproutID(id) {
		return ErrSproutIDInvalid
	}
	err := db.Transaction(func(tx *gorm.DB) error {
		found, err := retireSproutTx(tx, tenantID, id, "")
		if err != nil {
			return err
		}
		if !found {
			return ErrSproutIDNotFound
		}
		return nil
	})
	if err == nil {
		notifySproutLeftAccepted(tenantID, id)
	}
	return err
}

func DenyNKey(tenantID, id string) error {
	defer func() {
		if err := reloadNKeysFor(tenantID); err != nil {
			log.Errorf("failed to reload NATS auth for denied sprout %s in tenant %s: %v", id, tenantID, err)
		}
	}()
	if !IsValidSproutID(id) {
		return ErrSproutIDInvalid
	}
	row, err := findNKeyRowInTenant(tenantID, id)
	if err != nil {
		return err
	}
	if row.State == stateDenied {
		return ErrAlreadyDenied
	}
	return setStateInTenant(tenantID, id, stateDenied)
}

func UnacceptNKey(tenantID, id string, nkey string) error {
	defer func() {
		if err := reloadNKeysFor(tenantID); err != nil {
			log.Errorf("failed to reload NATS auth for unaccepted sprout %s in tenant %s: %v", id, tenantID, err)
		}
	}()
	if !IsValidSproutID(id) {
		return ErrSproutIDInvalid
	}
	row, err := findNKeyRowInTenant(tenantID, id)
	if nkey != "" && err == ErrSproutIDNotFound {
		return upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: id, NKey: nkey, State: stateUnaccepted})
	}
	if err != nil {
		return err
	}
	if row.State == stateUnaccepted {
		return ErrAlreadyUnaccepted
	}
	return setStateInTenant(tenantID, id, stateUnaccepted)
}

// GetNKeysByType returns every sprout in the given lifecycle state
// ("unaccepted"/"accepted"/"denied"/"rejected") within tenantID.
func GetNKeysByType(tenantID, set string) KeySet {
	return getNKeysByTypeForTenant(tenantID, set)
}

// getNKeysByTypeForTenant is GetNKeysByType's implementation, also used
// directly by tenant.go's per-tenant sync path (syncTenantSprouts).
func getNKeysByTypeForTenant(tenantID, set string) KeySet {
	keySet := KeySet{}
	keySet.Sprouts = []KeyManager{}
	switch set {
	case "unaccepted":
		fallthrough
	case "accepted":
		fallthrough
	case "denied":
		fallthrough
	case "rejected":
		// continue execution below default case
	default:
		return keySet
	}
	var rows []nkeyRow
	db.Where("tenant_id = ? AND state = ?", tenantID, set).Find(&rows)
	for _, r := range rows {
		keySet.Sprouts = append(keySet.Sprouts, KeyManager{SproutID: r.SproutID})
	}
	return keySet
}

func ListNKeysByType(tenantID string) KeysByType {
	var allKeys KeysByType
	allKeys.Accepted = GetNKeysByType(tenantID, "accepted")
	allKeys.Denied = GetNKeysByType(tenantID, "denied")
	allKeys.Rejected = GetNKeysByType(tenantID, "rejected")
	allKeys.Unaccepted = GetNKeysByType(tenantID, "unaccepted")
	return allKeys
}

func RejectNKey(tenantID, id string, nkey string) error {
	defer func() {
		if err := reloadNKeysFor(tenantID); err != nil {
			log.Errorf("failed to reload NATS auth for rejected sprout %s in tenant %s: %v", id, tenantID, err)
		}
	}()
	if !IsValidSproutID(id) {
		return ErrSproutIDInvalid
	}
	row, err := findNKeyRowInTenant(tenantID, id)
	if nkey != "" && err == ErrSproutIDNotFound {
		return upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: id, NKey: nkey, State: stateRejected})
	}
	if err != nil {
		return err
	}
	if row.State == stateRejected {
		return ErrAlreadyRejected
	}
	return setStateInTenant(tenantID, id, stateRejected)
}

func GetNKey(tenantID, id string) (string, error) {
	row, err := findNKeyRowInTenant(tenantID, id)
	if err != nil {
		return "", err
	}
	return row.NKey, nil
}

func NKeyExists(tenantID, id string, nkey string) (Registered bool, Matches bool) {
	return NKeyExistsInTenant(tenantID, id, nkey)
}

// maxRootCABytes caps how much of a /auth/cert/ response FetchRootCA reads.
// A root CA bundle is a few KiB; anything past this is not one.
const maxRootCABytes = 1 << 20

// FetchRootCA pins the farmer's root CA at filename by trust on first use:
// it fetches https://<FarmerInterface>:<FarmerAPIPort>/auth/cert/ without
// verifying the server, since there is no trusted certificate to verify
// against yet. If filename already exists it is kept as is and nothing is
// fetched, so whatever lands here is what every later connection trusts.
//
// The response is therefore only written when it is a 200 whose body is
// one or more PEM certificates and nothing else (validateRootCAPEM). It
// goes to a temporary file in the same directory first and is then linked
// into place (writeFileOnce), so a failed request, an error page (e.g. a
// DMZ proxy's "401 Jwt is missing") or a truncated body never becomes the
// pinned CA, and an existing file is never replaced. On any failure
// filename is left absent and the next call fetches again.
func FetchRootCA(filename string) error {
	_, err := os.Stat(filename)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	// InsecureSkipVerify is intentional: this is the TLS bootstrap path where
	// the sprout fetches the farmer's root CA for the first time. There is no
	// trusted certificate to verify against yet.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // TLS bootstrap
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * 10,
		// A redirect would only move the unverified fetch somewhere else;
		// surface it as a non-200 instead of following it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	certURL := fmt.Sprintf("https://%s:%s/auth/cert/", config.FarmerInterface, config.FarmerAPIPort)
	r, err := client.Get(certURL)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRootCABytes+1))
	if err != nil {
		return fmt.Errorf("%w: reading %s: %w", ErrRootCAFetch, certURL, err)
	}
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s returned %s: %q", ErrRootCAFetch, certURL, r.Status, snippet(body))
	}
	if len(body) > maxRootCABytes {
		return fmt.Errorf("%w: %s returned more than %d bytes", ErrRootCAFetch, certURL, maxRootCABytes)
	}
	if err := validateRootCAPEM(body); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrRootCAFetch, certURL, err)
	}
	// writeFileOnce never replaces an existing file, so a CA provisioned
	// out of band (or by a concurrent fetch) while this one was in flight
	// is kept rather than overwritten.
	if err := writeFileOnce(filename, body, 0o644); err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

// validateRootCAPEM reports whether data is one or more PEM CERTIFICATE
// blocks that each parse as X.509, separated only by whitespace. pem.Decode
// on its own skips any text before a block, so that is checked explicitly:
// a body with anything else in it is not a CA bundle and must not be
// pinned.
func validateRootCAPEM(data []byte) error {
	rest := data
	n := 0
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return fmt.Errorf("unexpected non-PEM content: %q", snippet(rest))
		}
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return errors.New("malformed PEM block")
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("unexpected PEM block type %q", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("certificate %d: %w", n+1, err)
		}
		n++
	}
	if n == 0 {
		return errors.New("no PEM certificate in response")
	}
	return nil
}

// snippet returns the start of b, for quoting an unexpected response in an
// error without copying an arbitrarily large body into the log.
func snippet(b []byte) string {
	const limit = 128
	if len(b) > limit {
		return string(b[:limit]) + "..."
	}
	return string(b)
}

func RootCACached(binary string) bool {
	var RootCA string
	switch binary {
	case "imas":
		RootCA = config.ImasRootCA
	case "sprout":
		RootCA = config.SproutRootCA
	}
	_, err := os.Stat(RootCA)
	return err == nil
}

var (
	nkeyClient   *http.Client
	nkeyClientMu sync.RWMutex
)

func LoadRootCA(binary string) error {
	client := &http.Client{}
	var RootCA string
	switch binary {
	case "imas":
		RootCA = config.ImasRootCA
	case "sprout":
		RootCA = config.SproutRootCA
		// With TOFU off (a DMZ install), the CA must have been provisioned
		// out of band; a missing file fails below instead of being fetched.
		if config.SproutRootCATOFU {
			if err := FetchRootCA(RootCA); err != nil {
				return err
			}
		}
	}
	certPool := x509.NewCertPool()
	rootPEM, err := os.ReadFile(RootCA)
	if binary == "sprout" && !config.SproutRootCATOFU && os.IsNotExist(err) {
		return fmt.Errorf("%w: %s does not exist and sproutrootcatofu is false; provision it with the CA that issued the farmer's (or DMZ edge's) TLS certificate",
			ErrRootCANotProvisioned, RootCA)
	}
	if err != nil || rootPEM == nil {
		return err
	}
	ok := certPool.AppendCertsFromPEM(rootPEM)
	if !ok {
		log.Errorf("nats: failed to parse root certificate from %q", RootCA)
		// Not re-fetched automatically: the file may have been provisioned
		// out of band, and replacing it with a trust-on-first-use fetch
		// would silently downgrade that pin. An operator has to fix it.
		return fmt.Errorf("%w: %s holds no usable PEM certificate; replace it, or delete it to fetch it again",
			ErrCannotParseRootCA, RootCA)
	}
	var nkeyTransport http.RoundTripper = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs:    certPool,
			MinVersion: tls.VersionTLS12,
		},
	}
	client.Transport = nkeyTransport
	client.Timeout = time.Second * 10
	nkeyClientMu.Lock()
	nkeyClient = client
	nkeyClientMu.Unlock()
	return nil
}

func PutNKey(id string) error {
	nkey, err := GetPubNKey(SproutPubNKey)
	if err != nil {
		return err
	}
	keySub := KeySubmission{NKey: nkey, SproutID: id}

	jw, err := json.Marshal(keySub)
	if err != nil {
		return fmt.Errorf("failed to marshal key submission: %w", err)
	}
	nkeyClientMu.RLock()
	client := nkeyClient
	nkeyClientMu.RUnlock()
	if client == nil {
		return ErrNKeyClientNotReady
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	url := config.FarmerURL + "/pki/putnkey"
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewBuffer(jw))
	if err != nil {
		return fmt.Errorf("failed to build NKey submission request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to submit NKey: %w", err)
	}
	resp.Body.Close()
	return nil
}

func GetPubNKey(keyType PubKeyType) (string, error) {
	var pubFile string
	switch keyType {
	case SproutPubNKey:
		pubFile = config.NKeySproutPubFile
	case FarmerPubNKey:
		pubFile = config.NKeyFarmerPubFile
		// case CliPubNKey:
		//	pubFile = config.NKeyImasPubFile
	}
	pubKeyBytes, err := os.ReadFile(pubFile)
	if err != nil {
		return "", err
	}
	return string(pubKeyBytes), nil
}

func GetSproutID() string {
	SproutID := config.SproutID
	if SproutID == "" {
		SproutID = createSproutID()
		config.SetSproutID(SproutID)
	}
	return SproutID
}
