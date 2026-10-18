package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/nats-io/nkeys"
	log "github.com/yogzblr/imas/internal/log"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/pki"
)

// GetNKeyNonce hands out the single-use server nonce a PutNKey
// submission signs (pki.IssueNKeyNonce). Registered only with PutNKey.
func GetNKeyNonce(w http.ResponseWriter, r *http.Request) {
	nonce, err := pki.IssueNKeyNonce()
	if err != nil {
		log.Warnf("NKey registration nonce: %v", err)
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	jw, _ := json.Marshal(pki.NKeyNonce{Nonce: nonce})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(jw)
}

// PutNKey handles NKey registration from sprouts during PKI bootstrap, on
// a standalone install with enrolment off (config "enrollment: false";
// with enrolment on, the Helm default, the route is not registered:
// security review 2026-10, L12). A sprout submits its public NKey over
// HTTPS with a signature, made with that NKey's seed, over a server nonce
// from GET /pki/nkeynonce (pki.VerifyNKeySubmission); a submission
// without one is refused with 403 before anything is stored. The farmer
// then stores the key in the appropriate state (unaccepted for new
// sprouts, rejected for sprouts presenting a different key than the one
// already on file).
//
// This is one of the few remaining HTTP endpoints — it cannot move to
// NATS because sprouts need to register before they have NATS credentials.
func PutNKey(w http.ResponseWriter, r *http.Request) {
	var submission pki.KeySubmission
	// grab the body the req
	err := json.NewDecoder(r.Body).Decode(&submission)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Trace("An invalid NKey request was made. Ignoring.")
		return
	}

	// verify our sprout id is valid
	if !pki.IsValidSproutID(submission.SproutID) || strings.Contains(submission.SproutID, "_") {
		log.Trace("An invalid Sprout ID was submitted. Ignoring.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// verify it's a valid NKey
	if !nkeys.IsValidPublicUserKey(submission.NKey) {
		log.Trace("An invalid NKey was submitted. Ignoring.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// and that the submitter holds its seed
	if err := pki.VerifyNKeySubmission(submission); err != nil {
		log.Warnf("An NKey submission for sprout %s did not prove possession of the NKey. Refusing.", submission.SproutID)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	// save it to the pki folder

	// check if the id exists in any of the folders
	// if it does, append a counter to the end, and check again
	// if we hit 100 sprouts with the same id, kick back a StatusBadRequest

	// PutNKey is the legacy pre-enrollment bootstrap path, scoped to the
	// single connection-level tenant reachable today — see
	// docs/design/imas-tenant-context-threading.md.
	tenantID := pki.CurrentTenantID()

	registered, matches := pki.NKeyExists(tenantID, submission.SproutID, submission.NKey)
	if registered && matches {
		log.Trace("A previously known NKey was submitted. Ignoring.")
		jw, _ := json.Marshal(apitypes.Inline{Success: true})
		w.WriteHeader(http.StatusOK)
		w.Write(jw)
		return
	}
	if !registered {
		log.Trace("A previously unknown NKey was submitted. Saving to Unaccepted.")
		pki.UnacceptNKey(tenantID, submission.SproutID, submission.NKey)
		jw, _ := json.Marshal(apitypes.Inline{Success: true})
		w.WriteHeader(http.StatusOK)
		w.Write(jw)
		return
	}
	// otherwise, it's registered and doesn't match
	for trailingIndex := 1; trailingIndex < 100; trailingIndex++ {
		registered, matches := pki.NKeyExists(tenantID, submission.SproutID+"_"+strconv.Itoa(trailingIndex), submission.NKey)
		if registered && matches {
			log.Trace("A previously known NKey was submitted. Ignoring.")
			jw, _ := json.Marshal(apitypes.Inline{Success: true})
			w.WriteHeader(http.StatusOK)
			w.Write(jw)
			return
		}
		if !registered {
			log.Trace("A previously accepted ID is presenting a new NKey. Saving to Rejected.")
			pki.RejectNKey(tenantID, submission.SproutID+"_"+strconv.Itoa(trailingIndex), submission.NKey)
			jw, _ := json.Marshal(apitypes.Inline{Success: true})
			w.WriteHeader(http.StatusOK)
			w.Write(jw)
			return
		}
	}
	// if there are more than 100 nkeys with the same id,
	// you're probably under attack
	log.Error("There are over 100 keys submitted with the same ID. Ignoring submission.")
	jw, _ := json.Marshal(apitypes.Inline{Success: false})
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write(jw)
}

// GetCertificate serves the farmer's root CA certificate.
// Sprouts fetch this during bootstrap to establish TLS trust.
func GetCertificate(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, config.RootCA)
}
