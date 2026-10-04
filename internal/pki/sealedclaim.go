package pki

// Cluster-wide single-use claims for sealed control-plane messages
// (docs/design/imas-payload-encryption-design.md, "Sealing the control
// plane", J.1). FLAG FOR SECURITY REVIEW.
//
// Each farmer replica keeps its own payloadbox.ReplayGuard, which stops a
// sealed request being replayed to the replica that already ran it. A
// request that changes state must also not run on a second replica, so it
// is claimed here first: SET NX on (tenant_id, principal, message id), in
// the Valkey and with the fail-closed rule claimSignedPayload
// (replaycache.go) already uses. A Valkey that can't be reached refuses
// every mutating request; read-only ones don't come here at all
// (internal/natsapi's sealedapi.go).
//
// The message ID is 128 random bits chosen inside the box, so nobody
// without the sender's key can learn one before the message is sent,
// let alone claim it in advance (the reason claimSignedPayload's key
// hashes the signature in).

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"
)

// SealedClaimTTL is how long a claim lives: twice payloadbox's ±5 minute
// freshness window, so a claim outlives every replica that could still
// accept the message, whichever way their clocks are off.
const SealedClaimTTL = 10 * time.Minute

// sealedClaimKeyPrefix namespaces sealed-message claims inside
// replayKeyPrefix.
const sealedClaimKeyPrefix = replayKeyPrefix + "sealed:"

var (
	// ErrSealedReplayed: the message was already claimed, on this replica
	// or another.
	ErrSealedReplayed = errors.New("pki: sealed message was already claimed")
	// ErrSealedClaimUnavailable: the claim couldn't be recorded (no
	// Valkey client, a Valkey error or timeout, malformed input). The
	// caller refuses the message: fail closed.
	ErrSealedClaimUnavailable = errors.New("pki: sealed message claim could not be recorded")
)

// claimComponentOK accepts the alphabets of every claim component: tenant
// IDs (and payloadbox.PlatformTenantID), sprout IDs, NKey public keys,
// payloadbox.PrincipalSaaSAPI and hex message IDs. None contains ':', so
// joining them with ':' is unambiguous.
func claimComponentOK(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '@':
		default:
			return false
		}
	}
	return true
}

// SealedClaimKey is the Valkey key ClaimSealedMessage writes.
func SealedClaimKey(tenantID, principal, msgID string) string {
	return sealedClaimKeyPrefix + tenantID + ":" + principal + ":" + msgID
}

// ClaimSealedMessage claims msgID, a sealed message principal sent in
// tenantID, cluster-wide. nil only for the first claim. A message claimed
// before is ErrSealedReplayed; anything else (malformed input, no client,
// a Valkey error) wraps ErrSealedClaimUnavailable. Either way the caller
// must refuse the message. Call it after the message opened and passed the
// replica's own ReplayGuard, and before acting on it.
func ClaimSealedMessage(ctx context.Context, tenantID, principal, msgID string) error {
	if !claimComponentOK(tenantID) || !claimComponentOK(principal) || !claimComponentOK(msgID) {
		return fmt.Errorf("%w: malformed claim", ErrSealedClaimUnavailable)
	}
	if replayClient == nil {
		return fmt.Errorf("%w: no Valkey client configured", ErrSealedClaimUnavailable)
	}
	ctx, cancel := context.WithTimeout(ctx, replayCacheTimeout)
	defer cancel()
	cmd := replayClient.B().Set().Key(SealedClaimKey(tenantID, principal, msgID)).Value("1").Nx().
		ExSeconds(int64(SealedClaimTTL / time.Second)).Build()
	err := replayClient.Do(ctx, cmd).Error()
	switch {
	case err == nil:
		return nil
	case valkey.IsValkeyNil(err):
		return ErrSealedReplayed
	default:
		return fmt.Errorf("%w: %w", ErrSealedClaimUnavailable, err)
	}
}
