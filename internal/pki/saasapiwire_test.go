package pki

// The internal.* wire (J.4): the subject -> purpose/method table both ends
// derive from, and the SaaS API box's wire-aware helpers.

import (
	"errors"
	"testing"

	"github.com/yogzblr/imas/internal/payloadbox"
)

func TestSaaSAPIWire(t *testing.T) {
	for subject, want := range map[string]SaaSAPIWire{
		"internal.tenant.provision":   {payloadbox.PurposeSaaSTenantProvision, "tenant.provision", "internal.tenant.provision"},
		"internal.tenant.deprovision": {payloadbox.PurposeSaaSTenantDeprovision, "tenant.deprovision", "internal.tenant.deprovision"},
		"internal.sprout.action":      {payloadbox.PurposeSaaSSproutAction, "sprout.action", "internal.sprout.action"},
	} {
		if got, ok := SaaSAPIRequestWire(subject); !ok || got != want {
			t.Errorf("%s: %+v %v", subject, got, ok)
		}
	}
	for _, subject := range []string{"internal.tenant.provisioned.pj_1", "imas.api.jobs.list", "internal.sprout.action.x", ""} {
		if _, ok := SaaSAPIRequestWire(subject); ok {
			t.Errorf("%q is a request subject", subject)
		}
	}
	if w := SproutActionReplyWire(); w.Purpose != payloadbox.PurposeSaaSSproutActionReply || w.Method != "sprout.action" || w.Subject != "internal.sprout.action" {
		t.Errorf("reply wire %+v", w)
	}
	w, err := TenantResultWire(true, "pj_1")
	if err != nil || w != (SaaSAPIWire{payloadbox.PurposeSaaSTenantDeprovisioned, "tenant.deprovisioned", "internal.tenant.deprovisioned.pj_1"}) {
		t.Errorf("deprovisioned wire %+v %v", w, err)
	}
	if w, _ := TenantResultWire(false, "pj_1"); w.Method != "tenant.provisioned" || w.Subject != "internal.tenant.provisioned.pj_1" {
		t.Errorf("provisioned wire %+v", w)
	}
	for _, bad := range []string{"", "pj.1", "pj*", "pj 1", "pj>"} {
		if _, err := TenantResultWire(false, bad); err == nil {
			t.Errorf("job id %q made a subject", bad)
		}
	}
}

func TestSaaSAPIBoxWireHelpers(t *testing.T) {
	_, saas := setupControlPlaneKeys(t)
	if _, _, err := saas.SealSaaSAPIRequest("internal.tenant.provisioned.pj_1", nil); err == nil {
		t.Error("sealed a request on a result subject")
	}
	data, id, err := saas.SealSaaSAPIRequest("internal.sprout.action", map[string]string{"tenant_id": "t_1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenFromSaaSAPI(payloadbox.PurposeSaaSSproutAction, "sprout.action", "internal.sprout.action", data); err != nil {
		t.Fatal(err)
	}
	// Two seals of the same request are two messages.
	if _, id2, _ := saas.SealSaaSAPIRequest("internal.sprout.action", map[string]string{"tenant_id": "t_1"}); id2 == id {
		t.Error("two seals shared a message id")
	}

	w := SproutActionReplyWire()
	reply, err := SealReplyToSaaSAPI(payloadbox.Reply{Purpose: w.Purpose, ReplyTo: id, Method: w.Method, Subject: w.Subject, Result: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := saas.OpenSproutActionReply("someotherid", reply); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("reply to another request: %v", err)
	}
	if b, err := saas.OpenSproutActionReply(id, reply); err != nil || string(b.Result) != `"ok"` {
		t.Errorf("own reply: %+v %v", b, err)
	}

	rw, _ := TenantResultWire(false, "pj_1")
	result, _, err := SealResultToSaaSAPI(payloadbox.Call{Purpose: rw.Purpose, Method: rw.Method, Subject: rw.Subject, Params: map[string]string{"job_id": "pj_1"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := saas.OpenTenantResult(false, "pj_2", rw.Subject, result); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("result for the wrong job id: %v", err)
	}
	if _, err := saas.OpenTenantResult(true, "pj_1", rw.Subject, result); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("provisioned result read as deprovisioned: %v", err)
	}
	if _, err := saas.OpenTenantResult(false, "pj_1", rw.Subject, result); err != nil {
		t.Errorf("genuine result: %v", err)
	}
	if _, err := saas.OpenTenantResult(false, "pj_1", rw.Subject, result); !errors.Is(err, payloadbox.ErrReplayed) {
		t.Errorf("replayed result: %v", err)
	}
}
