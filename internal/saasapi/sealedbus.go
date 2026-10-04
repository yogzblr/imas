package saasapi

// Sealed internal.* traffic, the SaaS API's end
// (docs/design/imas-payload-encryption-design.md, "Sealing the control
// plane", Decision B, J.4). FLAG FOR SECURITY REVIEW.
//
// Before J.4 farmer trusted the bus's account permissions on internal.*,
// and this service trusted whatever arrived on its result subjects and
// inboxes, so a compromised bus could provision or deprovision a tenant,
// run a command on any sprout, and forge the results. Now:
//
//   - Every request this service sends (internal.tenant.provision,
//     internal.tenant.deprovision, internal.sprout.action) is a payloadbox
//     Call sealed with its box key to the platform key(s) it pins, bound to
//     the request's purpose, method and subject (pki.SaaSAPIRequestWire),
//     with the tenant inside the box. Each send seals a new message: a new
//     random ID and the current time. A re-send (dispatch retrying after
//     no responders or farmer_busy, the outbox sweeper) is never a replay
//     of an earlier message, which farmer would refuse; idempotency stays
//     where CL.3 put it, on the job ID (provisioning) and the item's
//     queued -> dispatching claim (actions).
//   - Every answer it acts on must be sealed by farmer to its box key
//     under a pinned platform key: a provisioning result bound to its
//     job's subject, accepted once and within ±5 minutes
//     (pki.SaaSAPIBox.OpenTenantResult); an internal.sprout.action reply
//     bound by ReplyTo to the request it answers
//     (pki.SaaSAPIBox.OpenSproutActionReply). A plaintext answer, one that
//     doesn't open, or one bound to something else is refused, never a
//     result.
//
// Owner decisions, 2026-10-04: sealed only, with no plaintext fallback
// in either direction and no compatibility flag (internalallowplaintext
// is not built). ConnectBus refuses to connect without the box key and
// the platform pin.

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// controlBox is this service's box key and platform pin. Nil means
// nothing can be sealed, so nothing is sent.
var controlBox atomic.Pointer[pki.SaaSAPIBox]

// SetControlPlaneBox installs b, the box every internal.* request is
// sealed with and every reply and result opened with. ConnectBus calls it
// with the keys from the configuration; call it directly only in tests.
func SetControlPlaneBox(b *pki.SaaSAPIBox) { controlBox.Store(b) }

// errNoControlBox: no box key is installed, so no request can be sealed.
var errNoControlBox = errors.New("saasapi: no SaaS API box key installed (SAASAPI_BOX_PRIV_FILE); nothing is sent to farmer")

// loadControlPlaneBox reads the box key and the platform pin cfg names.
func loadControlPlaneBox(cfg Config) (*pki.SaaSAPIBox, error) {
	if cfg.BoxPrivFile == "" || len(cfg.PlatformBoxPubs) == 0 {
		return nil, fmt.Errorf("%w: SAASAPI_BOX_PRIV_FILE and SAASAPI_PLATFORM_BOX_PUB are required: farmer accepts only sealed requests", ErrBusNotConfigured)
	}
	b, err := pki.LoadSaaSAPIBox(cfg.BoxPrivFile, cfg.PlatformBoxPubs...)
	if err != nil {
		return nil, fmt.Errorf("saasapi: SAASAPI_BOX_PRIV_FILE / SAASAPI_PLATFORM_BOX_PUB: %w", err)
	}
	return b, nil
}

// sealedRequestMsg seals params as a new request on subject, ready to
// publish, and returns its message ID, which farmer's reply must name.
func sealedRequestMsg(subject string, params any) (*nats.Msg, string, error) {
	b := controlBox.Load()
	if b == nil {
		return nil, "", errNoControlBox
	}
	data, id, err := b.SealSaaSAPIRequest(subject, params)
	if err != nil {
		return nil, "", err
	}
	m := nats.NewMsg(subject)
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Header.Set(payloadbox.PrincipalHeader, payloadbox.PrincipalSaaSAPI)
	m.Data = data
	return m, id, nil
}

// errFarmerRefusedUnrun is a sealed internal.sprout.action reply that
// carries an error and no result: farmer opened the request but refused
// it before running anything (its replay store was unavailable). It is
// authenticated, so the item can safely go back to queued.
var errFarmerRefusedUnrun = errors.New("farmer refused the request before running it")

// openSproutActionReply opens msg, farmer's answer to the
// internal.sprout.action request whose ID is requestID, and returns the
// reply's result (a controlplane.SproutActionReply, as JSON), or
// errFarmerRefusedUnrun. Anything else is an error, and the caller can't
// tell whether the action ran:
//
//   - an Imas-Payload-Error refusal: unauthenticated by design (fixed
//     codes, no body), so a bus can forge one after delivering the
//     request;
//   - a plaintext reply;
//   - a sealed reply that doesn't open under this service's key and a
//     pinned platform key, or answers another request.
func openSproutActionReply(requestID string, msg *nats.Msg) (json.RawMessage, error) {
	if code := msg.Header.Get(payloadbox.ErrorHeader); code != "" {
		return nil, fmt.Errorf("farmer answered with refusal code %q (unauthenticated)", code)
	}
	if msg.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		return nil, errors.New("plaintext reply refused")
	}
	b := controlBox.Load()
	if b == nil {
		return nil, errNoControlBox
	}
	body, err := b.OpenSproutActionReply(requestID, msg.Data)
	if err != nil {
		return nil, fmt.Errorf("sealed reply refused: %w", err)
	}
	if len(body.Result) == 0 {
		if body.Error != "" {
			return nil, fmt.Errorf("%w: %s", errFarmerRefusedUnrun, body.Error)
		}
		return nil, errors.New("sealed reply with no result")
	}
	return body.Result, nil
}

// openTenantResult opens msg, a provisioning result that arrived on its
// subject for jobID, and returns the result. A plaintext result, one that
// doesn't open, one sealed for another job's subject, a stale one and a
// replayed one are all errors: nothing is applied.
func openTenantResult(jobType ProvisioningJobType, jobID string, msg *nats.Msg) (controlplane.TenantResult, error) {
	var res controlplane.TenantResult
	if msg.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		return res, errors.New("plaintext result refused")
	}
	b := controlBox.Load()
	if b == nil {
		return res, errNoControlBox
	}
	body, err := b.OpenTenantResult(jobType == ProvisioningJobDeprovision, jobID, msg.Subject, msg.Data)
	if err != nil {
		return res, fmt.Errorf("sealed result refused: %w", err)
	}
	if err := json.Unmarshal(body.Params, &res); err != nil {
		return res, fmt.Errorf("malformed sealed result: %w", err)
	}
	return res, nil
}
