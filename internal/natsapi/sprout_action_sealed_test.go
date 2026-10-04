package natsapi

// J.4 on internal.sprout.action (FLAG FOR SECURITY REVIEW): a compromised
// bus can't make farmer run a cmd.run, cook or self_update on any sprout,
// and can't read or forge farmer's answer. The point-of-effect checks
// behind the seal are covered in sprout_action_test.go and the SEC.5 and
// self_update tests, all of which now go through it.

import (
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// sendRaw sends m as a request from the SaaS API's connection and returns
// farmer's raw answer.
func sendRaw(t *testing.T, c *saasClient, m *nats.Msg) *nats.Msg {
	t.Helper()
	reply, err := c.nc.RequestMsg(m, 2*time.Second)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return reply
}

func wantSaaSRefusal(t *testing.T, name string, reply *nats.Msg, code string) {
	t.Helper()
	if got := reply.Header.Get(payloadbox.ErrorHeader); got != code {
		t.Errorf("%s: answered %q (headers %v, body %q), want %s", name, got, reply.Header, reply.Data, code)
	}
	if len(reply.Data) != 0 {
		t.Errorf("%s: a refusal with a body: %q", name, reply.Data)
	}
}

func TestSproutAction_RefusesForgedAndReplayed(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	var verified atomic.Int32
	rec := stubSproutActionDispatch(t, func(string, string) error { verified.Add(1); return nil })
	enableSelfUpdate(t)
	replicaB, err := nats.Connect(nc.ConnectedUrl())
	if err != nil {
		t.Fatal(err)
	}
	defer replicaB.Close()
	if err := registerSproutAction(nc, newSealedAPI()); err != nil {
		t.Fatal(err)
	}
	if err := registerSproutAction(replicaB, newSealedAPI()); err != nil {
		t.Fatal(err)
	}
	_ = replicaB.Flush()
	saas := dialSaaSAPI(t, nc)

	for _, action := range []controlplane.SproutActionRequest{
		cmdRunRequest("t_1", "web-01"),
		{TenantID: "t_1", SproutID: "web-01", Action: controlplane.SproutAction{Type: controlplane.ActionCook, Params: []byte(`{"recipe":"nginx"}`)}},
		{TenantID: "t_1", SproutID: "web-01", Action: controlplane.SproutAction{Type: controlplane.ActionSelfUpdate, Params: []byte(`{"version":"v9.9.9"}`)}},
	} {
		typ := action.Action.Type
		// Plaintext, as before J.4: the bus's account permissions are not
		// what farmer relies on.
		plain := nats.NewMsg(controlplane.SubjectSproutAction)
		plain.Data = mustJSON(t, action)
		wantSaaSRefusal(t, typ+": plaintext", sendRaw(t, saas, plain), payloadbox.ErrorCodeEncryptionRequired)

		// Sealed by a bus that made its own key.
		forged, _, err := sealedSaaSAPIMsg(impostorSaaSAPI(t, saas), controlplane.SubjectSproutAction, action)
		if err != nil {
			t.Fatal(err)
		}
		wantSaaSRefusal(t, typ+": impostor key", sendRaw(t, saas, forged), payloadbox.ErrorCodeOpenFailed)

		// Genuine, but claiming another principal.
		asUser, _ := saas.sealedMsg(t, controlplane.SubjectSproutAction, action)
		asUser.Header.Set(payloadbox.PrincipalHeader, "AUSER")
		wantSaaSRefusal(t, typ+": another principal", sendRaw(t, saas, asUser), payloadbox.ErrorCodeOpenFailed)

		// A genuine provisioning request moved onto this subject.
		moved, _ := saas.sealedMsg(t, controlplane.SubjectTenantProvision, action)
		moved.Subject = controlplane.SubjectSproutAction
		wantSaaSRefusal(t, typ+": moved from another subject", sendRaw(t, saas, moved), payloadbox.ErrorCodeOpenFailed)

		// Genuine with the box tampered with.
		tampered, _ := saas.sealedMsg(t, controlplane.SubjectSproutAction, action)
		tampered.Data = []byte(strings.Replace(string(tampered.Data), `"c":"`, `"c":"AAAA`, 1))
		wantSaaSRefusal(t, typ+": tampered", sendRaw(t, saas, tampered), payloadbox.ErrorCodeOpenFailed)
	}
	if verified.Load() != 0 || len(rec.all()) != 0 {
		t.Fatalf("a forged request was looked at (%d) or dispatched (%+v)", verified.Load(), rec.all())
	}

	// A genuine request runs once. Captured by the bus and replayed, to
	// whichever replica the queue group picks, it is refused every time:
	// the replica that ran it remembers it, and the other finds it
	// claimed in Valkey.
	genuine, id := saas.sealedMsg(t, controlplane.SubjectSproutAction, cmdRunRequest("t_1", "web-01"))
	first := sendRaw(t, saas, genuine)
	if r, err := saas.openSproutActionReply(id, first); err != nil || r.Status != controlplane.StatusCompleted {
		t.Fatalf("genuine: %+v, %v", r, err)
	}
	for i := 0; i < 6; i++ {
		replay := nats.NewMsg(genuine.Subject)
		replay.Header = nats.Header(http.Header(genuine.Header).Clone())
		replay.Data = genuine.Data
		wantSaaSRefusal(t, "replay", sendRaw(t, saas, replay), payloadbox.ErrorCodeOpenFailed)
	}
	if n := len(rec.all()); n != 1 {
		t.Fatalf("dispatched %d times, want 1", n)
	}
}

// Farmer's reply is sealed to the SaaS API and bound to the request: the
// bus sees no output, an answer to one request doesn't open as the answer
// to another, and a reply can't be passed back to farmer as a request.
func TestSproutAction_ReplyIsSealedAndBound(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	stubSproutActionDispatch(t, func(string, string) error { return nil })
	if err := RegisterSproutAction(nc); err != nil {
		t.Fatal(err)
	}
	saas := dialSaaSAPI(t, nc)

	m1, id1 := saas.sealedMsg(t, controlplane.SubjectSproutAction, cmdRunRequest("t_1", "web-01"))
	reply1 := sendRaw(t, saas, m1)
	_, id2 := saas.sealedMsg(t, controlplane.SubjectSproutAction, cmdRunRequest("t_1", "web-02"))
	if reply1.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		t.Fatalf("reply headers %v", reply1.Header)
	}
	for _, s := range []string{"web-01", "t_1", controlplane.StatusCompleted} {
		if strings.Contains(string(reply1.Data), s) {
			t.Fatalf("the reply shows %q on the bus", s)
		}
	}
	if _, err := saas.openSproutActionReply(id2, reply1); !errors.Is(err, payloadbox.ErrOpen) {
		t.Fatalf("an answer to another request: %v, want ErrOpen", err)
	}
	if r, err := saas.openSproutActionReply(id1, reply1); err != nil || r.SproutID != "web-01" {
		t.Fatalf("own answer: %+v, %v", r, err)
	}
	// Reflected back at farmer as a request.
	reflected := nats.NewMsg(controlplane.SubjectSproutAction)
	reflected.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	reflected.Header.Set(payloadbox.PrincipalHeader, payloadbox.PrincipalSaaSAPI)
	reflected.Data = reply1.Data
	wantSaaSRefusal(t, "reflected reply", sendRaw(t, saas, reflected), payloadbox.ErrorCodeOpenFailed)
}

// With Valkey down, a genuine request can't be claimed cluster-wide, so
// it isn't run; it opened, so the refusal goes back sealed, with no
// result, which the SaaS API reads as refused unrun.
func TestSproutAction_ValkeyDownRefusedSealed(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	rec := stubSproutActionDispatch(t, func(string, string) error { return nil })
	if err := RegisterSproutAction(nc); err != nil {
		t.Fatal(err)
	}
	saas := dialSaaSAPI(t, nc)
	saas.env.mr.SetError("down")
	m, id := saas.sealedMsg(t, controlplane.SubjectSproutAction, cmdRunRequest("t_1", "web-01"))
	reply := sendRaw(t, saas, m)
	body, err := saas.box.OpenSproutActionReply(id, reply.Data)
	if err != nil {
		t.Fatalf("opening the refusal: %v (headers %v)", err, reply.Header)
	}
	if body.Error == "" || len(body.Result) != 0 {
		t.Fatalf("refusal body %+v, want an error and no result", body)
	}
	if len(rec.all()) != 0 {
		t.Fatal("dispatched with Valkey down")
	}
}
