package main

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

func postJSON(h http.Handler, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return rec
}

func getManifest(h http.Handler, authz, query string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/sprout/update-manifest?"+query, nil)
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	h.ServeHTTP(rec, req)
	return rec
}

const testRelease = `{"version":"v0.2.0","os":"linux","arch":"amd64","package_type":"deb",
	"file_name":"imas-sprout_0.2.0_linux_amd64.deb","min_sprout_version":"v0.1.0",
	"checksum_sha256":"` + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" + `"}`

const testQuery = "os=linux&arch=amd64&package_type=deb&version=v0.2.0"

// TestUpdateManifest: a registered release is served, its checksums.txt
// signed by the key in
// the keyring the stub writes, only to a gateway JWT the stub minted, and
// only for the package type asked.
func TestUpdateManifest(t *testing.T) {
	f, h := newTestFarmer(t, 1)
	if rec := postJSON(h, "/_stub/release", testRelease); rec.Code != http.StatusOK {
		t.Fatalf("release = %d %s", rec.Code, rec.Body)
	}
	user, _ := nkeys.CreateUser()
	userPub, _ := user.PublicKey()
	_, gatewayJWT, err := f.mint(userPub, "web-01")
	if err != nil {
		t.Fatal(err)
	}

	rec := getManifest(h, "Bearer "+gatewayJWT, testQuery)
	if rec.Code != http.StatusOK {
		t.Fatalf("manifest = %d %s", rec.Code, rec.Body)
	}
	m, err := fleetsign.ParseManifest(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("not a strict manifest: %v", err)
	}
	ring, err := fleetsign.ParseArmoredKeyring(f.fleet.keyringJSON())
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.VerifyChecksums([]byte(m.ChecksumsTxt), m.Signature()); err != nil {
		t.Errorf("checksums.txt doesn't verify against the stub's keyring: %v", err)
	}
	sums, err := fleetsign.ParseChecksums([]byte(m.ChecksumsTxt))
	if err != nil {
		t.Fatal(err)
	}
	name, _ := fleetsign.ExpectedFileName(m.Version, m.OS, m.Arch, m.PackageType)
	if sum, ok := sums.Sum(name); !ok || sum != strings.Repeat("0123456789abcdef", 4) {
		t.Errorf("checksums.txt line for %s = %q, %v", name, sum, ok)
	}

	for name, c := range map[string]struct {
		authz, query string
		want         int
	}{
		"no token":        {"", testQuery, http.StatusUnauthorized},
		"foreign token":   {"Bearer eyJhbGciOiJFZERTQSJ9.e30.AAAA", testQuery, http.StatusForbidden},
		"other type":      {"Bearer " + gatewayJWT, strings.Replace(testQuery, "deb", "rpm", 1), http.StatusNotFound},
		"unknown version": {"Bearer " + gatewayJWT, strings.Replace(testQuery, "v0.2.0", "v0.9.0", 1), http.StatusNotFound},
	} {
		if rec := getManifest(h, c.authz, c.query); rec.Code != c.want {
			t.Errorf("%s: %d, want %d", name, rec.Code, c.want)
		}
	}
}

// TestUntrustedRelease: "signer": "untrusted" yields a manifest the
// keyring refuses.
func TestUntrustedRelease(t *testing.T) {
	f, h := newTestFarmer(t, 1)
	rec := postJSON(h, "/_stub/release", strings.Replace(testRelease, `"version"`, `"signer":"untrusted","version"`, 1))
	if rec.Code != http.StatusOK {
		t.Fatalf("release = %d %s", rec.Code, rec.Body)
	}
	m, err := fleetsign.ParseManifest(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	ring, _ := fleetsign.ParseArmoredKeyring(f.fleet.keyringJSON())
	if err := ring.VerifyChecksums([]byte(m.ChecksumsTxt), m.Signature()); err == nil {
		t.Error("an untrusted release verified")
	}
}

func TestSelfUpdateUnknownSprout(t *testing.T) {
	_, h := newTestFarmer(t, 1)
	if rec := postJSON(h, "/_stub/selfupdate", `{"sprout_id":"nobody","version":"v0.2.0"}`); rec.Code != http.StatusNotFound {
		t.Errorf("unknown sprout: %d", rec.Code)
	}
}

// The stub records a step event only once it opens under its tenant key
// and the sprout's box key, for the subject's job; plaintext and forged
// events are dropped.
func TestOpenStepEvent(t *testing.T) {
	f, _ := newTestFarmer(t, 1)
	sproutPub, sproutPriv, _ := box.GenerateKey(rand.Reader)
	f.sproutBox["web-01"] = sproutPub
	_, strangerPriv, _ := box.GenerateKey(rand.Reader)
	tenantPub, err := pki.DecodeBoxPubKey(f.tenantBoxPK)
	if err != nil {
		t.Fatal(err)
	}
	seal := func(priv *[32]byte, jid string) *nats.Msg {
		msg, _ := payloadbox.NewMessage(payloadbox.PurposeCookStep, stubTenantID, "web-01", "",
			cook.StepEvent{JobID: jid, Step: cook.StepCompletion{ID: "selfupdate-1", CompletionStatus: cook.StepCompleted}})
		data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: priv}})
		if err != nil {
			t.Fatal(err)
		}
		m := nats.NewMsg(cook.StepEventSubject("web-01", "job-1"))
		m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
		m.Data = data
		return m
	}
	step, jid, err := f.openStepEvent(seal(sproutPriv, "job-1"))
	if err != nil || jid != "job-1" || !strings.Contains(string(step), `"ID":"selfupdate-1"`) {
		t.Fatalf("honest event: %s %s %v", step, jid, err)
	}
	for name, m := range map[string]*nats.Msg{
		"plaintext":       {Subject: cook.StepEventSubject("web-01", "job-1"), Data: []byte(`{"ID":"selfupdate-1"}`)},
		"forged":          seal(strangerPriv, "job-1"),
		"for another job": seal(sproutPriv, "job-2"),
	} {
		if _, _, err := f.openStepEvent(m); err == nil {
			t.Errorf("%s event accepted", name)
		}
	}
}
