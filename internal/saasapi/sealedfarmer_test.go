package saasapi

// Farmer's end of sealed internal.* traffic, for this package's tests
// (J.4): the platform key, and the SaaS API box key every test's
// SaaS API seals with. The keys are made once per test binary and the
// SaaS API's end is installed for every test (init), as ConnectBus
// installs it in production; a test that needs it absent clears it.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/nats-io/nats.go"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// controlKeys is one deployment's control-plane keys.
type controlKeys struct {
	platformPub, platformPriv *[32]byte
	saasPub, saasPriv         *[32]byte
}

func newControlKeys() controlKeys {
	pp, pv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	sp, sv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return controlKeys{platformPub: pp, platformPriv: pv, saasPub: sp, saasPriv: sv}
}

// saasBox is the SaaS API's end of k.
func (k controlKeys) saasBox() *pki.SaaSAPIBox {
	b, err := pki.NewSaaSAPIBox(k.saasPriv, base64.StdEncoding.EncodeToString(k.platformPub[:]))
	if err != nil {
		panic(err)
	}
	return b
}

// farmerPairs is what farmer opens and seals SaaS API traffic with.
func (k controlKeys) farmerPairs() []payloadbox.KeyPair {
	return []payloadbox.KeyPair{{PeerPub: k.saasPub, Priv: k.platformPriv}}
}

// testKeys are this test binary's genuine keys.
var testKeys = newControlKeys()

func init() { SetControlPlaneBox(testKeys.saasBox()) }

// useControlBox installs b for the test and restores the genuine one.
func useControlBox(t *testing.T, b *pki.SaaSAPIBox) {
	t.Helper()
	SetControlPlaneBox(b)
	t.Cleanup(func() { SetControlPlaneBox(testKeys.saasBox()) })
}

// farmerOpenRequest opens msg, a request that arrived on its subject, as
// farmer does (purpose, method and subject bound, under the registered
// SaaS API key), decodes its params into into, and returns its message.
func farmerOpenRequest(msg *nats.Msg, into any) (*payloadbox.Message, error) {
	if msg.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 || msg.Header.Get(payloadbox.PrincipalHeader) != payloadbox.PrincipalSaaSAPI {
		return nil, fmt.Errorf("not a sealed SaaS API request: headers %v", msg.Header)
	}
	w, ok := pki.SaaSAPIRequestWire(msg.Subject)
	if !ok {
		return nil, fmt.Errorf("not a request subject: %s", msg.Subject)
	}
	m, body, err := payloadbox.OpenCall(msg.Data, testKeys.farmerPairs(), payloadbox.CallExpect{
		Purpose: w.Purpose, TenantID: payloadbox.PlatformTenantID, Principal: payloadbox.PrincipalSaaSAPI,
		Method: w.Method, Subject: w.Subject,
	})
	if err != nil {
		return nil, err
	}
	if into != nil {
		if err := json.Unmarshal(body.Params, into); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// sealFarmerReply is farmer's sealed f2a.sprout.action reply to the
// request whose ID is requestID, under keys k.
func (k controlKeys) sealFarmerReply(requestID string, result any, errText string) []byte {
	w := pki.SproutActionReplyWire()
	data, err := payloadbox.SealReply(payloadbox.Reply{
		Purpose: w.Purpose, TenantID: payloadbox.PlatformTenantID, Principal: payloadbox.PrincipalSaaSAPI,
		ReplyTo: requestID, Method: w.Method, Subject: w.Subject, Result: result, Error: errText,
	}, k.farmerPairs())
	if err != nil {
		panic(err)
	}
	return data
}

// farmerRespond answers msg, whose request ID is requestID, with result
// sealed as farmer seals it.
func farmerRespond(msg *nats.Msg, requestID string, result any) error {
	resp := nats.NewMsg(msg.Reply)
	resp.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	resp.Data = testKeys.sealFarmerReply(requestID, result, "")
	return msg.RespondMsg(resp)
}

// sealedResultMsg is farmer's sealed result res, for a job of jobType,
// on its job's subject, under keys k.
func (k controlKeys) sealedResultMsg(jobType ProvisioningJobType, res controlplane.TenantResult) *nats.Msg {
	w, err := pki.TenantResultWire(jobType == ProvisioningJobDeprovision, res.JobID)
	if err != nil {
		panic(err)
	}
	data, _, err := payloadbox.SealCall(payloadbox.Call{
		Purpose: w.Purpose, TenantID: payloadbox.PlatformTenantID, Principal: payloadbox.PrincipalSaaSAPI,
		Method: w.Method, Subject: w.Subject, Params: res,
	}, k.farmerPairs())
	if err != nil {
		panic(err)
	}
	m := nats.NewMsg(w.Subject)
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Data = data
	return m
}
