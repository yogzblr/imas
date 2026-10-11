package main

// Fleet update support, for the self-update end-to-end test
// (testing/selfupdate-e2e): just enough of farmer, saasapi and the release
// workflow for a packaged imas-sprout to receive a self_update job and
// install the signed release from a real package repository (P22: the
// release's GPG-signed checksums.txt).
//
//   - The stub holds a release GPG key itself and writes its armored
//     public key as the sprout keyring file (keyringJSON; main.go writes
//     it under -state-dir), which the test ships in the packages it
//     builds, the way the packages ship gpg-public-key.asc.
//   - POST /_stub/release registers a release, as the release workflow
//     and saasapi's operator plane do: it writes a checksums.txt with the
//     package's line, signs it with the release key, and stores the wire
//     manifest farmer serves. "signer": "untrusted" signs with a key no
//     keyring holds instead, for the refusal tests.
//   - GET /v1/sprout/update-manifest serves a registered manifest to a
//     sprout presenting a gateway JWT the stub minted, like farmer's
//     handler (one tenant, every version approved).
//   - POST /_stub/selfupdate sends a sprout the one-step selfupdate cook
//     job, sealed to it exactly as farmer seals a cook (internal/cook's
//     sealed.go), and checks its sealed acknowledgement.
//   - GET /_stub/fleet reports each sprout's last announced version
//     (imas.sprouts.announce.<id>) and every job's step events
//     (imas.cook.<id>.<jid>), which is what the test asserts on.
//
// With -repo-proxy-to, the stub also fronts a package repository (the
// test's Nexus) with TLS from a second CA it writes to
// -state-dir/repo-ca.pem, which the test installs in the sprout's OS trust
// store: SproutRootCA and the repository's trust root stay separate.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/lestrrat-go/jwx/v2/jwa"
	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// fleetState is the stub's release catalog and what it has seen sprouts
// report.
type fleetState struct {
	// trusted is the release key the keyring holds; untrusted is not in
	// it.
	trusted, untrusted *openpgp.Entity

	mu        sync.Mutex
	releases  map[releaseKey]fleetsign.Manifest
	announces map[string]string            // sprout ID -> last announced version tag
	events    map[string][]json.RawMessage // job ID -> step events, in arrival order
}

type releaseKey struct{ version, os, arch, packageType string }

// newFleetState makes the stub's release keys. Its argument is main.go's
// pre-P22 Ed25519 fleet key, which nothing uses any more; main.go stops
// passing it in P22 slice 2.
func newFleetState(_ ed25519.PrivateKey) (*fleetState, error) {
	trusted, err := newReleaseKey()
	if err != nil {
		return nil, err
	}
	untrusted, err := newReleaseKey()
	if err != nil {
		return nil, err
	}
	return &fleetState{
		trusted:   trusted,
		untrusted: untrusted,
		releases:  map[releaseKey]fleetsign.Manifest{},
		announces: map[string]string{},
		events:    map[string][]json.RawMessage{},
	}, nil
}

func newReleaseKey() (*openpgp.Entity, error) {
	return openpgp.NewEntity("imas stub release key", "", "release@stubfarmer.invalid", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
}

// keyringJSON is the sprout keyring (fleetsign.ParseArmoredKeyring): the
// trusted release key, ASCII-armored. The name is pre-P22 (main.go still
// calls it); the content is no longer JSON.
func (s *fleetState) keyringJSON() []byte {
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil
	}
	if err := s.trusted.Serialize(w); err != nil {
		return nil
	}
	if err := w.Close(); err != nil {
		return nil
	}
	return buf.Bytes()
}

// releaseRequest is POST /_stub/release's body: the release's identity
// and the package's checksums.txt line (file_name, checksum_sha256).
type releaseRequest struct {
	Version          string `json:"version"`
	OS               string `json:"os"`
	Arch             string `json:"arch"`
	PackageType      string `json:"package_type"`
	MinSproutVersion string `json:"min_sprout_version"`
	FileName         string `json:"file_name"`
	ChecksumSHA256   string `json:"checksum_sha256"`
	// Signer is "trusted" (default) or "untrusted".
	Signer string `json:"signer"`
}

func (f *farmer) release(w http.ResponseWriter, r *http.Request) {
	var req releaseRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	txt := []byte(req.ChecksumSHA256 + "  " + req.FileName + "\n")
	if _, err := fleetsign.ParseChecksums(txt); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	key := f.fleet.trusted
	if req.Signer == "untrusted" {
		key = f.fleet.untrusted
	}
	var sig bytes.Buffer
	if err := openpgp.DetachSign(&sig, key, bytes.NewReader(txt), nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	m := fleetsign.Manifest{
		Version: req.Version, OS: req.OS, Arch: req.Arch, PackageType: req.PackageType,
		MinSproutVersion: req.MinSproutVersion, ChecksumsTxt: string(txt),
		ChecksumsSig: base64.StdEncoding.EncodeToString(sig.Bytes()),
	}
	if err := m.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.fleet.mu.Lock()
	f.fleet.releases[releaseKey{m.Version, m.OS, m.Arch, m.PackageType}] = m
	f.fleet.mu.Unlock()
	log.Printf("fleet: registered %s %s/%s %s (%s), signed by the %s key", m.Version, m.OS, m.Arch, m.PackageType, req.FileName, signerName(req.Signer))
	writeJSON(w, m)
}

func signerName(s string) string {
	if s == "untrusted" {
		return "untrusted"
	}
	return "trusted"
}

// updateManifest is farmer's GET /v1/sprout/update-manifest, for a stub
// whose one tenant has approved every version.
func (f *farmer) updateManifest(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	parsed, err := jwxjwt.Parse([]byte(tok), jwxjwt.WithKey(jwa.EdDSA, f.gatewayKey.Public()), jwxjwt.WithValidate(true))
	if err != nil {
		log.Printf("update-manifest: rejected gateway JWT: %v", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	sproutID, _ := parsed.Get("sprout_id")
	q := r.URL.Query()
	key := releaseKey{q.Get("version"), q.Get("os"), q.Get("arch"), q.Get("package_type")}
	f.fleet.mu.Lock()
	m, found := f.fleet.releases[key]
	f.fleet.mu.Unlock()
	log.Printf("update-manifest: sprout %v asked for %+v: found %v", sproutID, key, found)
	if !found {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found"}` + "\n"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, m)
}

// selfUpdateRequest is POST /_stub/selfupdate's body.
type selfUpdateRequest struct {
	SproutID string `json:"sprout_id"`
	Version  string `json:"version"`
}

// selfUpdate sends sproutID the selfupdate job farmer's dispatch builds
// (internal/natsapi's sendSelfUpdate: one step, properties only
// {version}), sealed under the stub's tenant key to the sprout's box key.
func (f *farmer) selfUpdate(w http.ResponseWriter, r *http.Request) {
	var req selfUpdateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	sproutPub := f.sproutBox[req.SproutID]
	f.mu.Unlock()
	if sproutPub == nil || f.nc == nil {
		http.Error(w, "unknown sprout, or no bus connection", http.StatusNotFound)
		return
	}
	env := cook.RecipeEnvelope{
		JobID: cook.GenerateJobID(),
		Steps: []cook.Step{{
			Ingredient: cook.Ingredient(fleetsign.SelfUpdateIngredient),
			Method:     fleetsign.SelfUpdateMethod,
			ID:         cook.StepID(fleetsign.SelfUpdateStepIDPrefix + req.Version),
			Properties: map[string]interface{}{fleetsign.PropVersion: req.Version},
		}},
		DispatchedAt: time.Now().UTC(),
	}
	pair := []payloadbox.KeyPair{{PeerPub: sproutPub, Priv: f.tenantBoxPriv}}
	msg, err := payloadbox.NewMessage(payloadbox.PurposeCookRequest, stubTenantID, req.SproutID, "", env)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := payloadbox.Seal(msg, pair)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := nats.NewMsg(cook.CookSubject(req.SproutID))
	out.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	out.Data = data
	reply, err := f.nc.RequestMsg(out, 30*time.Second)
	if err != nil {
		http.Error(w, "sending the cook: "+err.Error(), http.StatusBadGateway)
		return
	}
	if code := reply.Header.Get(payloadbox.ErrorHeader); code != "" {
		http.Error(w, "sprout refused the sealed cook: "+code, http.StatusBadGateway)
		return
	}
	opened, err := payloadbox.Open(reply.Data, pair, payloadbox.Expect{Purpose: payloadbox.PurposeCookResponse, TenantID: stubTenantID, SproutID: req.SproutID})
	if err != nil || opened.ReplyTo != msg.ID {
		http.Error(w, fmt.Sprintf("opening the sprout's acknowledgement: %v", err), http.StatusBadGateway)
		return
	}
	var ack cook.Ack
	if err := json.Unmarshal(opened.Body, &ack); err != nil || !ack.Acknowledged || ack.JobID != env.JobID {
		http.Error(w, fmt.Sprintf("bad acknowledgement %+v: %v", ack, err), http.StatusBadGateway)
		return
	}
	log.Printf("fleet: sprout %s acknowledged self_update %s as job %s", req.SproutID, req.Version, env.JobID)
	writeJSON(w, map[string]string{"job_id": env.JobID})
}

// fleetReport is GET /_stub/fleet's body.
type fleetReport struct {
	Announces map[string]string            `json:"announces"`
	Events    map[string][]json.RawMessage `json:"events"`
}

func (f *farmer) fleetReport(w http.ResponseWriter, _ *http.Request) {
	f.fleet.mu.Lock()
	defer f.fleet.mu.Unlock()
	writeJSON(w, fleetReport{Announces: f.fleet.announces, Events: f.fleet.events})
}

// watchBus records sprout announcements and cook step events from nc.
func (f *farmer) watchBus(nc *nats.Conn) error {
	if _, err := nc.Subscribe("imas.sprouts.announce.*", func(m *nats.Msg) {
		var st config.Startup
		if err := json.Unmarshal(m.Data, &st); err != nil {
			return
		}
		f.fleet.mu.Lock()
		f.fleet.announces[st.SproutID] = st.Version.Tag
		f.fleet.mu.Unlock()
		log.Printf("fleet: sprout %s announced version %q", st.SproutID, st.Version.Tag)
	}); err != nil {
		return err
	}
	_, err := nc.Subscribe("imas.cook.*.*", func(m *nats.Msg) {
		parts := strings.Split(m.Subject, ".")
		jid := parts[len(parts)-1]
		f.fleet.mu.Lock()
		f.fleet.events[jid] = append(f.fleet.events[jid], json.RawMessage(append([]byte(nil), m.Data...)))
		f.fleet.mu.Unlock()
		log.Printf("fleet: job %s: %s", jid, m.Data)
	})
	return err
}
