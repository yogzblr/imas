package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	log "github.com/yogzblr/imas/internal/log"
)

var startTime time.Time

func init() {
	startTime = time.Now()
}

// HealthResponse is the JSON payload returned by the health endpoint.
// Valkey is "ok" when farmer holds a Valkey client, or "connecting" while
// it is still retrying the connection; it is informational only.
type HealthResponse struct {
	Status string `json:"status"`
	Uptime string `json:"uptime"`
	Valkey string `json:"valkey"`
}

// GetHealth is farmer's liveness endpoint (GET /health), unauthenticated,
// with uptime. It makes no network calls and always answers 200 while the
// process serves HTTP: nothing it could check is fixed by a restart.
//
// It used to fail (503) when farmer had no Valkey client, because
// initValkeyClient tried once at boot and only a restart retried. On a
// clean install Valkey can come up after farmer, and that kept the first
// farmer container at 503 until its startup probe killed it, minutes
// after everything else was ready (docs/briefs/W7-P30-first-install-
// startup-race.md). cmd/farmer's connectValkey now retries until it has a
// client, so a restart adds nothing. A missing client keeps the replica
// out of the Service through GetReady instead, which reports Valkey as
// "connecting" until it is installed.
func GetHealth(w http.ResponseWriter, _ *http.Request) {
	resp := HealthResponse{
		Status: "ok",
		Uptime: time.Since(startTime).Round(time.Second).String(),
		Valkey: readyCheckOK,
	}
	if !valkeyConfigured() {
		resp.Valkey = valkeyConnecting
	}
	jr, err := json.Marshal(resp)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jr)
}
