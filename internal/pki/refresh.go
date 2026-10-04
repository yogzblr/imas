package pki

// Gateway JWT refresh: POST /v1/refresh
// (docs/design/imas-envoy-enrollment-design.md, "Gateway JWT refresh").
//
// FLAG FOR SECURITY REVIEW. An enrolled sprout calls this to replace its
// short-lived gateway JWT (config.GatewayJWTTTL) before it expires. It is
// deliberately a separate contract from POST /v1/enroll: there is no join
// token field at all. It can only ever re-issue an existing, accepted
// identity; it never redeems a join token or creates a sprout. Envoy gives
// it its own route and rate-limit bucket, sized for the fleet's refresh
// volume, so refreshes and first-time enrollments never compete for one
// budget.
//
// Since J.2 the request is sealed with the sprout's box key and the reply
// sealed back to it (refreshsealed.go, RefreshSprout). The NKey-signed
// proof this file used to verify is refused: the NKey seed also signs the
// bus's CONNECT nonce, so a compromised bus could have one made.
//
// Every failure returns the same generic ErrEnrollmentFailed as Enroll
// (design doc §3.4), for the same reason: no oracle distinguishing an
// unknown nkey_pub from a bad proof or a stale timestamp.

import (
	"strconv"
	"strings"
)

// refreshSigDomain prefixed the NKey-signed refresh proof farmer accepted
// before J.2.
const refreshSigDomain = "imas-refresh-v1"

// RefreshSigningPayload returns the bytes a sprout signed with its NKey
// seed to refresh before J.2: refreshSigDomain, the timestamp and
// nkeyPub, newline-separated.
//
// Deprecated: farmer refuses this proof (RefreshSprout accepts only a
// sealed request), because a compromised bus can get the same signature
// made over a CONNECT nonce. It remains only so tests can build the old
// proof and show it is refused, and so ansible/molecule/stubfarmer, which
// still speaks the old contract and is outside J.2's scope, builds. Do
// not use it for anything new.
func RefreshSigningPayload(timestamp int64, nkeyPub string) []byte {
	return []byte(strings.Join([]string{
		refreshSigDomain,
		strconv.FormatInt(timestamp, 10),
		nkeyPub,
	}, "\n"))
}
