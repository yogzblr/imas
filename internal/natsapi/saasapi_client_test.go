package natsapi

// The SaaS API's end of sealed internal.* traffic, for natsapi's tests
// (J.4): what internal/saasapi puts on the bus and how it reads farmer's
// answers, built from the same pki helpers.

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// saasClient is the SaaS API: its bus connection, with its scoped inbox
// prefix, and its box key, made by the keygen Job in the sealed
// environment's mock OpenBao and pinned to the platform key farmer reads
// from there.
type saasClient struct {
	nc  *nats.Conn
	box *pki.SaaSAPIBox
	env *sealedEnv
}

// dialSaaSAPI sets up the sealed environment and the control-plane keys,
// and connects the way the SaaS API must: with its scoped inbox prefix, so
// request replies land under _INBOX.saasapi.
func dialSaaSAPI(t *testing.T, farmer *nats.Conn) *saasClient {
	t.Helper()
	env := setupSealedEnv(t)
	box := setupSaaSAPIKeys(t, env)
	nc, err := nats.Connect(farmer.ConnectedUrl(), nats.CustomInboxPrefix(controlplane.SaaSAPIInboxPrefix))
	if err != nil {
		t.Fatalf("connect SaaS API client: %v", err)
	}
	t.Cleanup(nc.Close)
	return &saasClient{nc: nc, box: box, env: env}
}

// sealedMsg is the message the SaaS API publishes on subject for params,
// and its ID.
func (c *saasClient) sealedMsg(t *testing.T, subject string, params any) (*nats.Msg, string) {
	t.Helper()
	m, id, err := sealedSaaSAPIMsg(c.box, subject, params)
	if err != nil {
		t.Fatal(err)
	}
	return m, id
}

func sealedSaaSAPIMsg(box *pki.SaaSAPIBox, subject string, params any) (*nats.Msg, string, error) {
	data, id, err := box.SealSaaSAPIRequest(subject, params)
	if err != nil {
		return nil, "", err
	}
	m := nats.NewMsg(subject)
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Header.Set(payloadbox.PrincipalHeader, payloadbox.PrincipalSaaSAPI)
	m.Data = data
	return m, id, nil
}

// request sends params as a sealed request on subject and returns farmer's
// raw answer and the request's ID.
func (c *saasClient) request(subject string, params any, timeout time.Duration) (*nats.Msg, string, error) {
	m, id, err := sealedSaaSAPIMsg(c.box, subject, params)
	if err != nil {
		return nil, "", err
	}
	reply, err := c.nc.RequestMsg(m, timeout)
	return reply, id, err
}

// errRefused is a farmer answer carrying a fixed Imas-Payload-Error code.
type errRefused struct{ code string }

func (e errRefused) Error() string { return "refused: " + e.code }

// openSproutActionReply is how the SaaS API reads farmer's answer to its
// request id: only a sealed reply that opens under its key and names id.
func (c *saasClient) openSproutActionReply(id string, msg *nats.Msg) (controlplane.SproutActionReply, error) {
	var out controlplane.SproutActionReply
	if code := msg.Header.Get(payloadbox.ErrorHeader); code != "" {
		return out, errRefused{code}
	}
	if msg.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		return out, fmt.Errorf("plaintext reply: %s", msg.Data)
	}
	body, err := c.box.OpenSproutActionReply(id, msg.Data)
	if err != nil {
		return out, err
	}
	if body.Error != "" {
		return out, errors.New("sealed refusal: " + body.Error)
	}
	if err := json.Unmarshal(body.Result, &out); err != nil {
		return out, err
	}
	return out, nil
}

// sproutAction sends req and returns farmer's opened reply.
func (c *saasClient) sproutAction(req controlplane.SproutActionRequest, timeout time.Duration) (controlplane.SproutActionReply, error) {
	msg, id, err := c.request(controlplane.SubjectSproutAction, req, timeout)
	if err != nil {
		return controlplane.SproutActionReply{}, err
	}
	return c.openSproutActionReply(id, msg)
}

func requestSproutAction(t *testing.T, c *saasClient, req controlplane.SproutActionRequest) controlplane.SproutActionReply {
	t.Helper()
	reply, err := c.sproutAction(req, 5*time.Second)
	if err != nil {
		t.Fatalf("request %s: %v", controlplane.SubjectSproutAction, err)
	}
	return reply
}

// openTenantResult is how the SaaS API reads a provisioning result that
// arrived on msg.Subject for jobID.
func (c *saasClient) openTenantResult(deprovision bool, jobID string, msg *nats.Msg) (controlplane.TenantResult, error) {
	var res controlplane.TenantResult
	if msg.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		return res, fmt.Errorf("plaintext result: %s", msg.Data)
	}
	body, err := c.box.OpenTenantResult(deprovision, jobID, msg.Subject, msg.Data)
	if err != nil {
		return res, err
	}
	err = json.Unmarshal(body.Params, &res)
	return res, err
}
