package pki

// Sealed refresh (J.2, Decision C), farmer's side and the client's
// handling of the reply. FLAG FOR SECURITY REVIEW. The enrollment
// client's end-to-end tests (enrollclient_test.go, sproutbox_test.go)
// drive the same code through RefreshGatewayJWT.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// sealedRefresh builds a fresh sealed refresh request for the sprout
// enrollForTest enrolled, and returns its message ID.
func sealedRefresh(t *testing.T) (RefreshRequest, string) {
	t.Helper()
	nkeyPub := sproutNKeyPub(t)
	sealed, id, err := SproutSealedRefresh("web-01", nkeyPub)
	if err != nil {
		t.Fatalf("SproutSealedRefresh: %v", err)
	}
	return RefreshRequest{NKeyPub: nkeyPub, Sealed: sealed}, id
}

// sealAsSprout seals msg with the enrolled sprout's current box key to
// its pinned tenant key, for requests a test needs to shape by hand.
func sealAsSprout(t *testing.T, msg payloadbox.Message) []byte {
	t.Helper()
	keys, err := loadSproutBoxKeys()
	if err != nil {
		t.Fatal(err)
	}
	defer keys.wipe()
	out, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: keys.tenantPub, Priv: keys.current}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func refreshMessage(t *testing.T, purpose, tenantID, sproutID, replyTo string, body any) payloadbox.Message {
	t.Helper()
	msg, err := payloadbox.NewMessage(purpose, tenantID, sproutID, replyTo, body)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestRefreshSprout_SealedRoundTrip(t *testing.T) {
	_, minter, store := enrollForTest(t)
	callsBefore := minter.calls
	req, id := sealedRefresh(t)
	reply, err := RefreshSprout(t.Context(), req)
	if err != nil {
		t.Fatalf("RefreshSprout: %v", err)
	}
	// Nothing in the reply is readable without the sprout's box key: it
	// is exactly a sealed envelope, whose only plaintext is its field
	// names, with no JWT in any key or string. (Not a substring search:
	// the ciphertext is random base64.)
	if err := checkSealedEnvelope(reply); err != nil {
		t.Errorf("the reply: %v", err)
	}
	if jwt, found, err := jwtInJSON(reply); err != nil || found {
		t.Errorf("the sealed reply carries a JWT in the clear: %q (%v)", jwt, err)
	}
	res, err := sproutOpenRefreshReply("web-01", id, reply)
	if err != nil {
		t.Fatalf("the sprout can't open farmer's reply: %v", err)
	}
	for _, v := range []string{res.GatewayJWT, res.JWT} {
		if _, ok := findJWT(v); !ok {
			t.Errorf("sealed %q is not recognized as a JWT, so the check above proves nothing", v)
		}
	}
	if res.SproutID != "web-01" || res.TenantID != "t_1" || res.JWT == "" || res.GatewayJWT == "" ||
		res.NKeyIdentity != req.NKeyPub || res.TenantX25519Pub != pinnedTenantKey(t) {
		t.Errorf("unexpected result %+v", res)
	}
	if minter.calls != callsBefore+1 {
		t.Errorf("gateway JWT mints = %d, want one more than the %d before", minter.calls, callsBefore)
	}
	if store.rows["ek_1"].UsedCount != 1 {
		t.Errorf("used_count = %d, want 1: refresh never touches the join token", store.rows["ek_1"].UsedCount)
	}
}

// A replayed refresh, to this replica or another sharing the Valkey, is
// refused; a fresh one from the same sprout still works.
func TestRefreshSprout_ReplayRefused(t *testing.T) {
	_, minter, _ := enrollForTest(t)
	req, _ := sealedRefresh(t)
	if _, err := RefreshSprout(t.Context(), req); err != nil {
		t.Fatalf("RefreshSprout: %v", err)
	}
	calls := minter.calls
	if _, err := RefreshSprout(t.Context(), req); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("replayed RefreshSprout = %v, want ErrEnrollmentFailed", err)
	}
	if minter.calls != calls {
		t.Error("a replayed refresh minted a gateway JWT")
	}
	fresh, _ := sealedRefresh(t)
	if _, err := RefreshSprout(t.Context(), fresh); err != nil {
		t.Fatalf("a fresh refresh after the replay: %v", err)
	}
}

// Every request that isn't exactly a fresh, sealed refresh from this
// sprout is refused, mints nothing and claims nothing.
func TestRefreshSprout_Rejections(t *testing.T) {
	_, minter, _ := enrollForTest(t)
	mr := withTestReplayCache(t)
	nkeyPub := sproutNKeyPub(t)
	stranger, _ := nkeys.CreateUser()
	strangerPub, _ := stranger.PublicKey()
	body := sealedRefreshBody{NKeyPub: nkeyPub, Timestamp: time.Now().Unix()}
	good, _ := sealedRefresh(t)

	attacker := newTestBoxKeyPair(t)
	keys, err := loadSproutBoxKeys()
	if err != nil {
		t.Fatal(err)
	}
	tenantPub := keys.tenantPub
	keys.wipe()
	sealedByAttacker, _ := payloadbox.Seal(refreshMessage(t, payloadbox.PurposeRefresh, "t_1", "web-01", "", body),
		[]payloadbox.KeyPair{{PeerPub: tenantPub, Priv: attacker.priv}})

	var env payloadbox.Envelope
	if err := json.Unmarshal(good.Sealed, &env); err != nil {
		t.Fatal(err)
	}
	env.Copies = append(env.Copies, env.Copies[0], env.Copies[0])
	threeCopies, _ := json.Marshal(env)

	// What a compromised bus can get: the sprout's NKey signature over
	// the old refresh proof, from a CONNECT nonce.
	ts := time.Now().Unix()
	kp, err := loadSproutNKey()
	if err != nil {
		t.Fatal(err)
	}
	nkeySig, _ := kp.Sign(RefreshSigningPayload(ts, nkeyPub))
	kp.Wipe()
	nkeyProof, _ := json.Marshal(map[string]any{"timestamp": ts, "nkey_sig": base64.RawURLEncoding.EncodeToString(nkeySig)})
	sigAsString, _ := json.Marshal(base64.RawURLEncoding.EncodeToString(nkeySig))

	cases := map[string]RefreshRequest{
		"the NKey proof as the sealed field":   {NKeyPub: nkeyPub, Sealed: nkeyProof},
		"the bare NKey signature":              {NKeyPub: nkeyPub, Sealed: sigAsString},
		"unknown nkey_pub":                     {NKeyPub: strangerPub, Sealed: good.Sealed},
		"malformed nkey_pub":                   {NKeyPub: "not-a-key", Sealed: good.Sealed},
		"empty":                                {NKeyPub: nkeyPub},
		"not JSON":                             {NKeyPub: nkeyPub, Sealed: json.RawMessage(`nope`)},
		"more copies than a sprout sends":      {NKeyPub: nkeyPub, Sealed: threeCopies},
		"sealed by another box key":            {NKeyPub: nkeyPub, Sealed: sealedByAttacker},
		"a reply, not a request":               {NKeyPub: nkeyPub, Sealed: sealAsSprout(t, refreshMessage(t, payloadbox.PurposeRefresh, "t_1", "web-01", "0123456789abcdef0123456789abcdef", body))},
		"another purpose (a cmd.run reply)":    {NKeyPub: nkeyPub, Sealed: sealAsSprout(t, refreshMessage(t, payloadbox.PurposeCmdRunResponse, "t_1", "web-01", "", body))},
		"farmer's own reply purpose reflected": {NKeyPub: nkeyPub, Sealed: sealAsSprout(t, refreshMessage(t, payloadbox.PurposeRefreshReply, "t_1", "web-01", "", body))},
		"naming another tenant":                {NKeyPub: nkeyPub, Sealed: sealAsSprout(t, refreshMessage(t, payloadbox.PurposeRefresh, "t_2", "web-01", "", body))},
		"naming another sprout":                {NKeyPub: nkeyPub, Sealed: sealAsSprout(t, refreshMessage(t, payloadbox.PurposeRefresh, "t_1", "web-02", "", body))},
		"naming another NKey":                  {NKeyPub: nkeyPub, Sealed: sealAsSprout(t, refreshMessage(t, payloadbox.PurposeRefresh, "t_1", "web-01", "", sealedRefreshBody{NKeyPub: strangerPub, Timestamp: time.Now().Unix()}))},
		"a stale body timestamp":               {NKeyPub: nkeyPub, Sealed: sealAsSprout(t, refreshMessage(t, payloadbox.PurposeRefresh, "t_1", "web-01", "", sealedRefreshBody{NKeyPub: nkeyPub, Timestamp: time.Now().Add(-EnrollSigMaxSkew - time.Minute).Unix()}))},
	}
	calls := minter.calls
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := RefreshSprout(t.Context(), req); !errors.Is(err, ErrEnrollmentFailed) {
				t.Errorf("RefreshSprout = %v, want ErrEnrollmentFailed", err)
			}
		})
	}
	if minter.calls != calls {
		t.Errorf("gateway JWT mints = %d, want %d: no rejected refresh may mint", minter.calls, calls)
	}
	if keys := mr.Keys(); len(keys) != 0 {
		t.Errorf("rejected refreshes claimed %v", keys)
	}
	// The good request was never spent by any of that.
	if _, err := RefreshSprout(t.Context(), good); err != nil {
		t.Errorf("the good request after all that: %v", err)
	}
}

// The old refresh proof's signature (the domain a compromised bus can
// still get signed over a CONNECT nonce) must not pass as an enrollment
// signature either.
func TestEnroll_RejectsRefreshSignature(t *testing.T) {
	enrollForTest(t)
	kp, err := loadSproutNKey()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Wipe()
	req := signedEnroll(t, kp, "ek_1.s", "web-01", testEnrollBoxPub(t))
	refreshSig, _ := kp.Sign(RefreshSigningPayload(req.Timestamp, req.NKeyPub))
	req.NKeySig = base64.RawURLEncoding.EncodeToString(refreshSig)
	if _, err := Enroll(t.Context(), req); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("Enroll accepted a refresh-domain signature: %v", err)
	}
}

// Clock skew: farmer accepts a request issued up to EnrollSigMaxSkew
// either side of its own clock, and nothing beyond.
func TestRefreshSprout_ClockSkew(t *testing.T) {
	enrollForTest(t)
	for _, c := range []struct {
		farmerAhead time.Duration
		ok          bool
	}{
		{0, true},
		{EnrollSigMaxSkew - time.Minute, true},
		{-(EnrollSigMaxSkew - time.Minute), true},
		{EnrollSigMaxSkew + time.Minute, false},
		{-(EnrollSigMaxSkew + time.Minute), false},
	} {
		req, _ := sealedRefresh(t)
		withEnrollNow(t, time.Now().Add(c.farmerAhead))
		_, err := RefreshSprout(t.Context(), req)
		if c.ok && err != nil {
			t.Errorf("farmer's clock %s from the sprout's: %v, want accepted", c.farmerAhead, err)
		}
		if !c.ok && !errors.Is(err, ErrEnrollmentFailed) {
			t.Errorf("farmer's clock %s from the sprout's: %v, want ErrEnrollmentFailed", c.farmerAhead, err)
		}
	}
}

// A refresh that can't be claimed (no Valkey) is refused: fail closed.
func TestRefreshSprout_FailsClosedWithoutValkey(t *testing.T) {
	enrollForTest(t)
	req, _ := sealedRefresh(t)
	SetReplayCacheClient(nil)
	if _, err := RefreshSprout(t.Context(), req); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("RefreshSprout without Valkey = %v, want ErrEnrollmentFailed", err)
	}
}

// A denied sprout, and one whose box key farmer no longer has on record,
// can't refresh: the second must re-enroll.
func TestRefreshSprout_DeniedOrNoBoxKeyRefused(t *testing.T) {
	t.Run("denied", func(t *testing.T) {
		enrollForTest(t)
		req, _ := sealedRefresh(t)
		if err := DenyNKey("t_1", "web-01"); err != nil {
			t.Fatal(err)
		}
		if _, err := RefreshSprout(t.Context(), req); !errors.Is(err, ErrEnrollmentFailed) {
			t.Fatalf("RefreshSprout for a denied sprout = %v, want ErrEnrollmentFailed", err)
		}
	})
	t.Run("no box key on record", func(t *testing.T) {
		enrollForTest(t)
		req, _ := sealedRefresh(t)
		if err := db.Where("tenant_id = ? AND sprout_id = ?", "t_1", "web-01").Delete(&sproutBoxKeyRow{}).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := RefreshSprout(t.Context(), req); !errors.Is(err, ErrEnrollmentFailed) {
			t.Fatalf("RefreshSprout with no box key on record = %v, want ErrEnrollmentFailed", err)
		}
	})
}

// The sprout accepts only the reply to the request it just sent, sealed
// for it under its pinned tenant key.
func TestSproutOpenRefreshReply_BoundToItsRequest(t *testing.T) {
	enrollForTest(t)
	reqA, idA := sealedRefresh(t)
	_, idB := sealedRefresh(t)
	replyA, err := RefreshSprout(t.Context(), reqA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sproutOpenRefreshReply("web-01", idB, replyA); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("the reply to another request opened: %v", err)
	}
	if _, err := sproutOpenRefreshReply("web-02", idA, replyA); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("the reply opened as another sprout's: %v", err)
	}
	// The sprout's own request reflected back as the reply.
	if _, err := sproutOpenRefreshReply("web-01", idA, reqA.Sealed); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("the sprout's own request opened as a reply: %v", err)
	}
	if _, err := sproutOpenRefreshReply("web-01", idA, replyA); err != nil {
		t.Errorf("the right reply: %v", err)
	}
}

// A sprout with no box key of its own, or a pin missing, can't make a
// sealed refresh at all. That is fatal: it must re-enroll.
func TestRefreshGatewayJWT_NoBoxKeyIsFatal(t *testing.T) {
	for name, remove := range map[string]func() string{
		"box key":   func() string { return config.SproutBoxPrivFile },
		"sprout ID": SproutIDFile,
	} {
		t.Run(name, func(t *testing.T) {
			srv, _, _ := enrollForTest(t)
			if err := os.Remove(remove()); err != nil {
				t.Fatal(err)
			}
			_, err := RefreshGatewayJWT(t.Context())
			if !IsFatalRefreshError(err) {
				t.Fatalf("RefreshGatewayJWT = %v, want a fatal error", err)
			}
			if n := srv.refreshCount(); n != 0 {
				t.Errorf("sent %d refresh requests, want none", n)
			}
		})
	}
}

// An expired gateway JWT (a sprout off for longer than its lifetime) is
// no obstacle: the sealed refresh needs none, and the next websocket
// handshake (GatewayJWTHeaders, which nats.go calls on every reconnect)
// presents the new one. This is what the bus reconnect path relies on.
func TestRefreshGatewayJWT_RecoversFromAnExpiredToken(t *testing.T) {
	_, minter, _ := enrollForTest(t)
	expired := installGatewayJWT(t, minter, time.Now().Add(-time.Hour))
	if _, err := RefreshGatewayJWT(t.Context()); err != nil {
		t.Fatalf("RefreshGatewayJWT with an expired token: %v", err)
	}
	h, err := GatewayJWTHeaders()
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimPrefix(h.Get("Authorization"), "Bearer ")
	if tok == expired || !gatewayJWTFresh(tok, time.Now()) {
		t.Error("the next handshake would still present the expired token")
	}
}
