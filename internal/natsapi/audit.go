package natsapi

import (
	"encoding/json"

	"github.com/yogzblr/imas/internal/audit"
)

func handleAuditList(_ string, params json.RawMessage) (any, error) {
	l := audit.Global()
	if l == nil {
		return nil, errAuditNotConfigured
	}
	dates, err := l.ListDates()
	if err != nil {
		return nil, err
	}
	return dates, nil
}

func handleAuditQuery(_ string, params json.RawMessage) (any, error) {
	l := audit.Global()
	if l == nil {
		return nil, errAuditNotConfigured
	}

	var p audit.QueryParams
	if len(params) > 0 {
		json.Unmarshal(params, &p)
	}

	result, err := l.Query(p)
	if err != nil {
		return nil, err
	}
	return result, nil
}

var errAuditNotConfigured = auditError("audit logging not configured")

type auditError string

func (e auditError) Error() string { return string(e) }
