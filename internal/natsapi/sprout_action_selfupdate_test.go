package natsapi

// self_update on internal.sprout.action (design doc §2.5, FLAG FOR
// SECURITY REVIEW): farmer re-verifies the release signature against the
// imas-fleet-signing public key before anything reaches a sprout, and
// refuses — never dispatches checksum-only — when the signature is
// missing, invalid, or can't be checked.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/pki"
)

const suChecksum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

type staticKeys struct {
	ks  fleetsign.KeySet
	err error
}

func (s staticKeys) KeySet(context.Context) (fleetsign.KeySet, error) { return s.ks, s.err }

// withTestManifestFields stands in for the manifest fields a self_update
// request doesn't carry yet (selfUpdateManifestFields).
func withTestManifestFields(t *testing.T) {
	t.Helper()
	orig := selfUpdateManifestFields
	selfUpdateManifestFields = testManifestFields
	t.Cleanup(func() { selfUpdateManifestFields = orig })
}

func testManifestFields(controlplane.SelfUpdateParams) (osName, arch, fileName, minSproutVersion string) {
	return "linux", "amd64", "imas-sprout_2.4.1_amd64.deb", "v2.0.0"
}

// signedSelfUpdate returns a release signed with a fresh key, and a key
// source holding that key, with the test manifest fields installed.
func signedSelfUpdate(t *testing.T) (controlplane.SelfUpdateParams, staticKeys, ed25519.PrivateKey) {
	t.Helper()
	withTestManifestFields(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := fleetsign.NewKeySet([]fleetsign.PublicKey{{Version: 1, Key: pub}})
	p := controlplane.SelfUpdateParams{
		Version:        "v2.4.1",
		ArtifactURL:    "https://artifacts.example.com/sprout-v2.4.1-linux-amd64",
		ChecksumSHA256: suChecksum,
	}
	p.Signature = signParams(t, priv, p)
	return p, staticKeys{ks: ks}, priv
}

func signParams(t *testing.T, priv ed25519.PrivateKey, p controlplane.SelfUpdateParams) string {
	t.Helper()
	osName, arch, fileName, minSproutVersion := testManifestFields(p)
	msg, err := fleetsign.Manifest{Version: p.Version, OS: osName, Arch: arch, FileName: fileName,
		ChecksumSHA256: p.ChecksumSHA256, MinSproutVersion: minSproutVersion}.Message()
	if err != nil {
		t.Fatal(err)
	}
	return fleetsign.EncodeSignature(1, ed25519.Sign(priv, msg))
}

func selfUpdateRequest(t *testing.T, tenantID, sproutID string, p controlplane.SelfUpdateParams) []byte {
	t.Helper()
	return mustJSON(t, controlplane.SproutActionRequest{
		TenantID: tenantID, SproutID: sproutID,
		Action: controlplane.SproutAction{Type: controlplane.ActionSelfUpdate, Params: mustJSON(t, p)},
	})
}

func TestSelfUpdate_ValidSignatureDispatches(t *testing.T) {
	rec := stubSproutActionDispatch(t, func(string, string) error { return nil })
	p, keys, _ := signedSelfUpdate(t)
	SetFleetKeySource(keys)

	reply := handleSproutAction(selfUpdateRequest(t, "t_1", "web-01", p))
	if reply.Status != controlplane.StatusDispatched || reply.JID != "jid-su" || reply.ErrorCode != "" {
		t.Fatalf("reply = %+v", reply)
	}
	calls := rec.all()
	var sent controlplane.SelfUpdateParams
	if len(calls) != 1 || calls[0].tenantID != "t_1" || json.Unmarshal(calls[0].params, &sent) != nil || sent != p {
		t.Fatalf("dispatched %+v", calls)
	}
}

// The core refusal cases. Each must fail before dispatch.
func TestSelfUpdate_RefusedBeforeDispatch(t *testing.T) {
	good, keys, priv := signedSelfUpdate(t)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherKeys, _ := fleetsign.NewKeySet([]fleetsign.PublicKey{{Version: 1, Key: otherPub}})

	tampered := good
	tampered.ChecksumSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // hash still well-formed, signature now wrong

	resignedForOtherRow := good
	resignedForOtherRow.Signature = signParams(t, priv, tampered) // valid signature, but over a different row

	unsigned := good
	unsigned.Signature = "" // an un-migrated fleet_versions row

	for _, tc := range []struct {
		name string
		p    controlplane.SelfUpdateParams
		keys fleetsign.KeySetSource
		want controlplane.ErrorCode
	}{
		{"tampered row, valid hash, invalid signature", tampered, keys, controlplane.ErrorInvalidRequest},
		{"signature for a different row", resignedForOtherRow, keys, controlplane.ErrorInvalidRequest},
		{"missing signature (un-migrated row)", unsigned, keys, controlplane.ErrorInvalidRequest},
		{"malformed signature", func() controlplane.SelfUpdateParams { p := good; p.Signature = "vault:v1:xx"; return p }(), keys, controlplane.ErrorInvalidRequest},
		{"signed by a key farmer doesn't trust", good, staticKeys{ks: otherKeys}, controlplane.ErrorInvalidRequest},
		{"no key source configured", good, nil, controlplane.ErrorInternal},
		{"Transit unreachable", good, staticKeys{err: errors.New("dial tcp: refused")}, controlplane.ErrorInternal},
		{"http artifact url", func() controlplane.SelfUpdateParams {
			p := good
			p.ArtifactURL = "http://artifacts.example.com/x"
			return p
		}(), keys, controlplane.ErrorInvalidRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := stubSproutActionDispatch(t, func(string, string) error { return nil })
			SetFleetKeySource(tc.keys)
			reply := handleSproutAction(selfUpdateRequest(t, "t_1", "web-01", tc.p))
			if reply.Status != controlplane.StatusFailed || reply.ErrorCode != tc.want {
				t.Fatalf("reply = %+v, want failed/%s", reply, tc.want)
			}
			if calls := rec.all(); len(calls) != 0 {
				t.Fatalf("refused release was dispatched: %+v", calls)
			}
		})
	}
}

// Until the sprout resolves its own manifest (FU.2), a self_update
// request can't supply the signed os, arch, file_name and
// min_sprout_version, so farmer refuses every one before reading keys or
// dispatching, even one whose signature would verify with them filled in.
func TestSelfUpdate_FailsClosedWithoutManifestFields(t *testing.T) {
	p, keys, _ := signedSelfUpdate(t)
	selfUpdateManifestFields = func(controlplane.SelfUpdateParams) (string, string, string, string) { return "", "", "", "" }
	rec := stubSproutActionDispatch(t, func(string, string) error { return nil })
	SetFleetKeySource(keys)
	reply := handleSproutAction(selfUpdateRequest(t, "t_1", "web-01", p))
	if reply.Status != controlplane.StatusFailed || reply.ErrorCode != controlplane.ErrorInvalidRequest {
		t.Fatalf("reply = %+v, want failed/invalid_request", reply)
	}
	if calls := rec.all(); len(calls) != 0 {
		t.Fatalf("dispatched without a complete manifest: %+v", calls)
	}
}

// The point-of-effect tenant check still runs first: a sprout in another
// tenant is not found, even for a perfectly signed release.
func TestSelfUpdate_TenantCheckStillApplies(t *testing.T) {
	rec := stubSproutActionDispatch(t, func(tenant, _ string) error {
		if tenant != "t_a" {
			return pki.ErrSproutIDNotFound
		}
		return nil
	})
	p, keys, _ := signedSelfUpdate(t)
	SetFleetKeySource(keys)
	if reply := handleSproutAction(selfUpdateRequest(t, "t_b", "web-01", p)); reply.ErrorCode != controlplane.ErrorSproutNotFound {
		t.Fatalf("reply = %+v", reply)
	}
	if len(rec.all()) != 0 {
		t.Fatal("dispatched to a sprout outside the asserted tenant")
	}
}

// Through the real sendSelfUpdate and cook.SendStepsEvent: the sprout
// receives exactly one selfupdate step carrying the signature, over the
// tenant's own connection.
func TestSelfUpdate_ThroughRealDispatch(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	setupNatsAPIPKI(t)
	legacy := pki.CurrentTenantID()
	writeNKey(t, "", "accepted", "web-01", "UKEY_WEB01")
	cook.RegisterFarmerNatsConn(legacy, nc)
	defer cook.UnregisterFarmerNatsConn(legacy)
	p, keys, _ := signedSelfUpdate(t)
	origK := fleetKeys
	SetFleetKeySource(keys)
	defer SetFleetKeySource(origK)

	got := make(chan cook.RecipeEnvelope, 1)
	if _, err := nc.Subscribe("imas.sprouts.web-01.cook", func(msg *nats.Msg) {
		var env cook.RecipeEnvelope
		_ = json.Unmarshal(msg.Data, &env)
		got <- env
		ack, _ := json.Marshal(cook.Ack{Acknowledged: true, JobID: env.JobID})
		_ = msg.Respond(ack)
	}); err != nil {
		t.Fatal(err)
	}
	if err := RegisterSproutAction(nc); err != nil {
		t.Fatal(err)
	}
	// The handler's SUB must reach the server before the SaaS API
	// connection's request does.
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	reply := requestSproutAction(t, dialSaaSAPI(t, nc), controlplane.SproutActionRequest{
		TenantID: legacy, SproutID: "web-01",
		Action: controlplane.SproutAction{Type: controlplane.ActionSelfUpdate, Params: mustJSON(t, p)},
	})
	if reply.Status != controlplane.StatusDispatched || reply.JID == "" {
		t.Fatalf("reply = %+v", reply)
	}
	env := <-got
	if env.JobID != reply.JID || len(env.Steps) != 1 {
		t.Fatalf("envelope = %+v", env)
	}
	step := env.Steps[0]
	if step.Ingredient != fleetsign.SelfUpdateIngredient || step.Method != fleetsign.SelfUpdateMethod ||
		step.Properties[fleetsign.PropSignature] != p.Signature || step.Properties[propArtifactURL] != p.ArtifactURL ||
		step.Properties[fleetsign.PropChecksumSHA256] != p.ChecksumSHA256 || step.Properties[fleetsign.PropVersion] != p.Version {
		t.Fatalf("step = %+v", step)
	}
}
