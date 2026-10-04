package main

// Fleet update support, for the self-update end-to-end test
// (testing/selfupdate-e2e): just enough of farmer, saasapi and
// fleetreleaser for a packaged imas-sprout to receive a self_update job
// and install the signed release from a real package repository.
//
//   - The stub holds the imas-fleet-signing key itself (key version 1) and
//     writes its public half as the sprout keyring file
//     (-state-dir/fleet-signing-keys.json), which the test ships in the
//     packages it builds, the way a release stamps
//     packaging/etc/fleet-signing-keys.json.
//   - POST /_stub/release signs and registers a manifest, as saasapi's
//     operator plane does with fleetreleaser. "signer": "untrusted" signs
//     with a key no keyring holds instead, for the refusal tests.
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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

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
	trusted, untrusted ed25519.PrivateKey

	mu        sync.Mutex
	releases  map[releaseKey]fleetsign.Manifest
	announces map[string]string            // sprout ID -> last announced version tag
	events    map[string][]json.RawMessage // job ID -> step events, in arrival order
}

type releaseKey struct{ version, os, arch, packageType string }

func newFleetState(trusted ed25519.PrivateKey) (*fleetState, error) {
	_, untrusted, err := ed25519.GenerateKey(rand.Reader)
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

// keyringJSON is the sprout keyring (fleetsign.ParseKeyring) holding the
// trusted key as key id 1.
func (s *fleetState) keyringJSON() []byte {
	pub := s.trusted.Public().(ed25519.PublicKey)
	b, _ := json.Marshal(map[string]string{"1": base64.StdEncoding.EncodeToString(pub)})
	return b
}

// releaseRequest is POST /_stub/release's body.
type releaseRequest struct {
	fleetsign.Manifest
	PackageType string `json:"package_type"`
	// Signer is "trusted" (default) or "untrusted".
	Signer string `json:"signer"`
}

func (f *farmer) release(w http.ResponseWriter, r *http.Request) {
	var req releaseRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	m := req.Manifest
	msg, err := m.Message()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	key := f.fleet.trusted
	if req.Signer == "untrusted" {
		key = f.fleet.untrusted
	}
	m.Signature = fleetsign.EncodeSignature(1, ed25519.Sign(key, msg))
	f.fleet.mu.Lock()
	f.fleet.releases[releaseKey{m.Version, m.OS, m.Arch, req.PackageType}] = m
	f.fleet.mu.Unlock()
	log.Printf("fleet: registered %s %s/%s %s (%s), signed by the %s key", m.Version, m.OS, m.Arch, req.PackageType, m.FileName, signerName(req.Signer))
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
