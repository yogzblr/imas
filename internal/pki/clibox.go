package pki

// Farmer's end of sealed imas CLI <-> farmer traffic
// (docs/design/imas-payload-encryption-design.md, "Sealing the control
// plane", Decision A, J.1): the key lookups around payloadbox's
// OpenCall/SealReply, as farmerbox.go is for sprouts. FLAG FOR SECURITY
// REVIEW.
//
// A user's request in tenant T is sealed with the user's CLI box key to
// T's tenant box key. Farmer opens it with T's keys (current, and the
// previous one inside a rotation's grace window) against the user's CLI
// box keys registered in T (internal/auth's store: the active one, and
// one in its grace window), always looked up by (tenant_id, user_id). A
// user with no key registered in T can't make a sealed request there,
// and nothing falls back to a weaker check. Replies are sealed to the
// user's active key only.
//
// Not wired into the router yet (rollout step 4): internal/natsapi's
// sealedapi.go has the NATS side.

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// CLIAPISubjectPrefix is the subject prefix of every CLI request
// (internal/natsapi's SubjectPrefix, which this package can't import).
const CLIAPISubjectPrefix = "imas.api."

// MethodAuthRotateKey is the method a CLI box key rotation is sent on
// (imas auth rotate-key, purpose c2f.userkey.pub). Mutating, and not
// routed until rollout step 4.
const MethodAuthRotateKey = "auth.rotatekey"

// cliUserKeyBody is a c2f.userkey.pub submission's body.
type cliUserKeyBody struct {
	Pub string `json:"pub"`
}

// OpenFromCLI opens data, a Call the user userID sealed in tenantID under
// purpose for method on subject. It tries the user's active CLI box key
// first and then each grace key on its own, against every tenant key, and
// returns the key that opened it (sealedUnder), which a key rotation
// needs. Any failure to open, including a user with no key, is
// payloadbox.ErrOpen; freshness and replay are the caller's.
func OpenFromCLI(tenantID, userID, purpose, method, subject string, data []byte) (msg *payloadbox.Message, body *payloadbox.CallBody, sealedUnder string, err error) {
	active, grace, err := auth.ValidCLIBoxKeys(tenantID, userID)
	if err != nil {
		if errors.Is(err, auth.ErrNoActiveCLIBoxKey) {
			return nil, nil, "", payloadbox.ErrOpen
		}
		return nil, nil, "", err
	}
	want := payloadbox.CallExpect{Purpose: purpose, TenantID: tenantID, Principal: userID, Method: method, Subject: subject}
	try := func() (*payloadbox.Message, *payloadbox.CallBody, string, error) {
		tenantKeys, err := TenantBoxKeys(tenantID)
		if err != nil {
			return nil, nil, "", err
		}
		for _, k := range append([]string{active}, grace...) {
			pub, err := auth.DecodeCLIBoxPub(k)
			if err != nil {
				continue
			}
			candidates := make([]payloadbox.KeyPair, 0, len(tenantKeys))
			for _, tk := range tenantKeys {
				candidates = append(candidates, payloadbox.KeyPair{PeerPub: pub, Priv: tk.Priv})
			}
			if msg, body, err := payloadbox.OpenCall(data, candidates, want); err == nil {
				return msg, body, k, nil
			}
		}
		return nil, nil, "", payloadbox.ErrOpen
	}
	msg, body, sealedUnder, err = try()
	if !errors.Is(err, payloadbox.ErrOpen) || !tenantBoxCachedLongerThan(tenantID, tenantBoxRereadAfter) {
		return msg, body, sealedUnder, err
	}
	// The CLI may have re-pinned to a key another replica rotated to.
	InvalidateTenantBoxKeys(tenantID)
	return try()
}

// SealToCLI seals r, farmer's reply to a CLI request (its tenant and
// principal are set here), to userID's active CLI box key in tenantID,
// one copy per tenant key.
func SealToCLI(tenantID, userID string, r payloadbox.Reply) ([]byte, error) {
	active, _, err := auth.ValidCLIBoxKeys(tenantID, userID)
	if err != nil {
		return nil, err
	}
	pub, err := auth.DecodeCLIBoxPub(active)
	if err != nil {
		return nil, err
	}
	tenantKeys, err := TenantBoxKeys(tenantID)
	if err != nil {
		return nil, err
	}
	pairs := make([]payloadbox.KeyPair, 0, len(tenantKeys))
	for _, tk := range tenantKeys {
		pairs = append(pairs, payloadbox.KeyPair{PeerPub: pub, Priv: tk.Priv})
	}
	r.TenantID, r.Principal = tenantID, userID
	return payloadbox.SealReply(r, pairs)
}

// ErrBoxKeyClaimed means a box public key is already some principal's
// (a sprout's box key, a user's CLI box key) or is a tenant or the
// platform key. Two principals sharing a key would share the secret
// derived with farmer; the purposes already keep their messages apart,
// and this is defence in depth.
var ErrBoxKeyClaimed = errors.New("pki: box public key is already registered to a principal or is a farmer-side key")

// checkBoxPubUnclaimed refuses pub if it is any sprout's box key in any
// tenant (by pub alone, deliberately: the question is whether any
// principal holds it), tenantID's tenant key, or the platform key. A user
// CLI key collision is the auth store's unique index. Fails closed: a key
// it can't check is refused.
func checkBoxPubUnclaimed(tenantID, pub string) error {
	var n int64
	if err := db.Model(&sproutBoxKeyRow{}).Where("pub = ?", pub).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return ErrBoxKeyClaimed
	}
	tenantKeys, err := TenantBoxKeys(tenantID)
	if err != nil {
		return err
	}
	for _, tk := range tenantKeys {
		if encodeBoxPub(tk.Pub) == pub {
			return ErrBoxKeyClaimed
		}
	}
	platform, err := PlatformBoxKeys()
	switch {
	case errors.Is(err, ErrPlatformBoxNotProvisioned):
	case err != nil:
		return err
	default:
		for _, pk := range platform {
			if encodeBoxPub(pk.Pub) == pub {
				return ErrBoxKeyClaimed
			}
		}
	}
	return nil
}

// RegisterCLIBoxKey registers pub as userID's first CLI box key in
// tenantID: the admin path (auth.users.add carrying the new user's key,
// rollout step 4). It refuses a key any principal holds, or a farmer-side
// key, then records it (auth.RegisterCLIBoxKey).
func RegisterCLIBoxKey(tenantID, userID, pub string) error {
	if !IsValidTenantID(tenantID) {
		return fmt.Errorf("pki: invalid tenant id %q", tenantID)
	}
	if _, err := auth.DecodeCLIBoxPub(pub); err != nil {
		return err
	}
	if err := checkBoxPubUnclaimed(tenantID, pub); err != nil {
		return err
	}
	return auth.RegisterCLIBoxKey(tenantID, userID, pub)
}

// RecordCLIBoxKeySubmission records the key named in a c2f.userkey.pub
// submission (body, opened by OpenFromCLI under sealedUnder) as userID's
// active CLI box key in tenantID. The old key keeps opening requests for
// auth.CLIBoxKeyGraceDuration. See auth.RecordCLIBoxKeySubmission for
// which submissions may change the active key. It returns the new key.
func RecordCLIBoxKeySubmission(tenantID, userID, sealedUnder string, body *payloadbox.CallBody) (string, error) {
	var sub cliUserKeyBody
	if body == nil || json.Unmarshal(body.Params, &sub) != nil || sub.Pub == "" {
		return "", errors.New("pki: CLI box key submission has no key")
	}
	if _, err := auth.DecodeCLIBoxPub(sub.Pub); err != nil {
		return "", err
	}
	active, _, err := auth.ValidCLIBoxKeys(tenantID, userID)
	if err != nil {
		return "", err
	}
	if sub.Pub != active {
		if err := checkBoxPubUnclaimed(tenantID, sub.Pub); err != nil {
			return "", err
		}
	}
	return sub.Pub, auth.RecordCLIBoxKeySubmission(tenantID, userID, sealedUnder, sub.Pub, auth.CLIBoxKeyGraceDuration)
}
