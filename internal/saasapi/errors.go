package saasapi

import (
	"encoding/json"
	"net/http"

	log "github.com/yogzblr/imas/internal/log"
)

// errorResponse matches the design doc's standard error shape (§1):
//
//	{ "error": "<snake_case_code>", "message": "<human readable>", "details": {} }
type errorResponse struct {
	Error   string         `json:"error"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeErrorDetails(w, status, code, message, nil)
}

func writeErrorDetails(w http.ResponseWriter, status int, code, message string, details map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(errorResponse{Error: code, Message: message, Details: details})
	if err != nil {
		log.Errorf("saasapi: writing error response: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Errorf("saasapi: writing JSON response: %v", err)
	}
}
