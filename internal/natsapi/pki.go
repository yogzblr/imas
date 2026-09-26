package natsapi

import (
	"encoding/json"

	"github.com/yogzblr/imas/internal/pki"
)

func handlePKIList(tenantID string, _ json.RawMessage) (any, error) {
	return pki.ListNKeysByType(tenantID), nil
}

func handlePKIAccept(tenantID string, params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	err := pki.AcceptNKey(tenantID, km.SproutID)
	if err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func handlePKIReject(tenantID string, params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	err := pki.RejectNKey(tenantID, km.SproutID, "")
	if err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func handlePKIDeny(tenantID string, params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	err := pki.DenyNKey(tenantID, km.SproutID)
	if err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func handlePKIUnaccept(tenantID string, params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	err := pki.UnacceptNKey(tenantID, km.SproutID, "")
	if err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func handlePKIDelete(tenantID string, params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	err := pki.DeleteNKey(tenantID, km.SproutID)
	if err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}
