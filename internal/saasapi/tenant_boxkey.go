package saasapi

// The tenant key fingerprint in a join token (security review 2026-10,
// L24; internal/jointoken). FLAG FOR SECURITY REVIEW.
//
// A sprout pins the tenant box public key its first enrollment response
// names. That response crosses the DMZ Envoy, so on its own the pin is
// trust on first use against the Envoy. The token the sprout enrolls
// with now carries the key's SHA-256 fingerprint, and the sprout refuses
// a response whose key doesn't match it before pinning anything. This
// service learns the key from farmer over the sealed control plane
// (internal.tenant.boxkey, sealedbus.go), never through the Envoy, and
// mints no token when it can't.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/jointoken"
)

// tenantBoxKeyTimeout bounds the wait for farmer's answer. Farmer reads
// the key from OpenBao (a few milliseconds); a variable for tests.
var tenantBoxKeyTimeout = 10 * time.Second

// errTenantKeyUnavailable means farmer couldn't be asked, or didn't give
// a usable answer: the caller may try again.
var errTenantKeyUnavailable = errors.New("saasapi: the tenant's box key could not be read from farmer")

// errTenantKeyDeprovisioned means farmer has the tenant deprovisioned: a
// token for it would enroll nothing.
var errTenantKeyDeprovisioned = errors.New("saasapi: farmer has the tenant deprovisioned")

// tenantKeyFingerprintFor is what CreateEnrollmentKey asks: farmer,
// over the package bus. A variable so this package's tests that aren't
// about it can answer without a farmer (sealedfarmer_test.go's init).
var tenantKeyFingerprintFor = func(ctx context.Context, tenantID string) (string, error) {
	return tenantKeyFingerprint(ctx, bus, tenantID)
}

// tenantKeyFingerprint asks farmer for tenantID's current box public key
// and returns its fingerprint (jointoken.FingerprintB64).
func tenantKeyFingerprint(ctx context.Context, nc *nats.Conn, tenantID string) (string, error) {
	if nc == nil {
		return "", fmt.Errorf("%w: not connected to the bus", errTenantKeyUnavailable)
	}
	req, reqID, err := sealedRequestMsg(controlplane.SubjectTenantBoxKey, controlplane.TenantBoxKeyRequest{TenantID: tenantID})
	if err != nil {
		return "", fmt.Errorf("%w: sealing the request: %v", errTenantKeyUnavailable, err)
	}
	ctx, cancel := context.WithTimeout(ctx, tenantBoxKeyTimeout)
	defer cancel()
	msg, err := nc.RequestMsgWithContext(ctx, req)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %v", errTenantKeyUnavailable, controlplane.SubjectTenantBoxKey, err)
	}
	reply, err := openTenantBoxKeyReply(reqID, msg)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errTenantKeyUnavailable, err)
	}
	if reply.TenantID != tenantID {
		return "", fmt.Errorf("%w: the reply names tenant %q", errTenantKeyUnavailable, reply.TenantID)
	}
	switch reply.ErrorCode {
	case "":
	case controlplane.ErrorTenantNotFound:
		return "", errTenantKeyDeprovisioned
	default:
		return "", fmt.Errorf("%w: farmer answered %s", errTenantKeyUnavailable, reply.ErrorCode)
	}
	fp, err := jointoken.FingerprintB64(reply.TenantX25519Pub)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errTenantKeyUnavailable, err)
	}
	return fp, nil
}
