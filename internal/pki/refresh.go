package pki

// Gateway JWT refresh: POST /v1/refresh
// (docs/design/imas-envoy-enrollment-design.md, "Gateway JWT refresh").
//
// FLAG FOR SECURITY REVIEW. An enrolled sprout calls this to replace its
// short-lived gateway JWT (config.GatewayJWTTTL) before it expires. It is
// deliberately a separate contract from POST /v1/enroll: there is no join
// token field at all, only nkey_pub and a timestamped proof of possession
// of its seed. It can only ever re-issue an existing, accepted identity;
// it never redeems a join token or creates a sprout. Envoy gives it its
// own route and rate-limit bucket, sized for the fleet's refresh volume,
// so refreshes and first-time enrollments never compete for one budget.
//
// Each signed refresh request is single-use (claimSignedPayload,
// replaycache.go), the same as an enrollment request.
//
// Every failure returns the same generic ErrEnrollmentFailed as Enroll
// (design doc §3.4), for the same reason: no oracle distinguishing an
// unknown nkey_pub from a bad signature or a stale timestamp.

import (
	"context"
	"strconv"
	"strings"

	"github.com/nats-io/nkeys"

	log "github.com/yogzblr/imas/internal/log"
)

// refreshSigDomain prefixes every refresh signing payload. It differs
// from enrollSigDomain so a signature made for one endpoint can never be
// accepted by the other. Bump its version for any change to
// RefreshSigningPayload's layout.
const refreshSigDomain = "imas-refresh-v1"

// RefreshRequest carries one POST /v1/refresh request's fields into
// RefreshSprout. NKeySig is the sprout's NKey seed's signature over
// RefreshSigningPayload(Timestamp, NKeyPub), unpadded base64url, with the
// same ±EnrollSigMaxSkew timestamp window as enrollment.
type RefreshRequest struct {
	NKeyPub   string
	Timestamp int64
	NKeySig   string
}

// RefreshSigningPayload returns the exact bytes a sprout signs to refresh
// its gateway JWT: refreshSigDomain, the timestamp and nkeyPub,
// newline-separated, with no trailing newline.
func RefreshSigningPayload(timestamp int64, nkeyPub string) []byte {
	return []byte(strings.Join([]string{
		refreshSigDomain,
		strconv.FormatInt(timestamp, 10),
		nkeyPub,
	}, "\n"))
}

// RefreshSprout verifies req's proof of possession and, for an accepted
// sprout, returns its existing NATS User JWT, a freshly minted gateway
// JWT, its tenant ID (EnrollResult.TenantID, which the sprout checks
// against the tenant it pinned at enrollment) and the tenant X25519
// public key. An unknown, denied, rejected or
// deleted nkey_pub fails like every other failure, and so does a
// resubmission of an earlier request.
func RefreshSprout(ctx context.Context, req RefreshRequest) (*EnrollResult, error) {
	if !nkeys.IsValidPublicUserKey(req.NKeyPub) {
		log.Warnf("refresh: rejected malformed nkey_pub")
		return nil, ErrEnrollmentFailed
	}
	payload := RefreshSigningPayload(req.Timestamp, req.NKeyPub)
	sig, err := verifyTimestampedNKeySig(req.NKeyPub, req.Timestamp, req.NKeySig, payload)
	if err != nil {
		log.Warnf("refresh: rejected proof of possession for nkey_pub %s: %v", req.NKeyPub, err)
		return nil, ErrEnrollmentFailed
	}
	tenantID, sproutID, err := SproutIDAndTenantForNKey(req.NKeyPub)
	if err != nil {
		log.Warnf("refresh: nkey_pub %s is not an accepted sprout", req.NKeyPub)
		return nil, ErrEnrollmentFailed
	}
	// Claimed only once the nkey_pub is known to be an accepted sprout's,
	// so a caller signing with a throwaway NKey can't write keys.
	if err := claimSignedPayload(ctx, payload, sig, req.Timestamp); err != nil {
		log.Warnf("refresh: rejected resubmitted or unrecordable signed request for nkey_pub %s: %v", req.NKeyPub, err)
		return nil, ErrEnrollmentFailed
	}
	res, err := reissueExistingIdentity(ctx, tenantID, sproutID, req.NKeyPub)
	if err != nil {
		return nil, err
	}
	log.Debugf("refresh: issued a fresh gateway JWT for sprout %s", sproutID)
	return res, nil
}
