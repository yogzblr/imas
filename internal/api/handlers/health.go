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
// Valkey is "ok" when farmer holds a Valkey client, or "not configured"
// when it doesn't; see GetHealth for why that's the only dependency
// liveness looks at.
type HealthResponse struct {
	Status string `json:"status"`
	Uptime string `json:"uptime"`
	Valkey string `json:"valkey"`
}

// GetHealth is farmer's liveness endpoint (GET /health), unauthenticated,
// with uptime. It makes no network calls and fails (503, "unhealthy") only
// when restarting the process is what would fix the problem.
//
// The one such case is Valkey: if farmer couldn't create its Valkey client
// at boot (cmd/farmer/main.go's initHeartbeatClient), it never retries, so
// the replica stays broken, and permanently not ready on GET /ready,
// until something restarts it. Failing liveness here makes kubelet do
// that. It checks only that the client exists, never that Valkey answers.
// A client that exists reconnects on its own. And every replica shares one
// Valkey, so a reachability check here would restart the whole fleet
// during a Valkey outage without fixing it. Reachability is GetReady's
// job: it takes the pod out of the Service instead.
func GetHealth(w http.ResponseWriter, _ *http.Request) {
	resp := HealthResponse{
		Status: "ok",
		Uptime: time.Since(startTime).Round(time.Second).String(),
		Valkey: readyCheckOK,
	}
	code := http.StatusOK
	if !valkeyConfigured() {
		resp.Status = "unhealthy"
		resp.Valkey = errNotConfigured.Error()
		code = http.StatusServiceUnavailable
	}
	jr, err := json.Marshal(resp)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(jr)
}
