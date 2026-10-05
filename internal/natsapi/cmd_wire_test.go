package natsapi

// imas.api.cmd.run's reply on the wire: a per-sprout error travels as its
// message, so the CLI shows farmer's refusal to send to a keyless sprout
// ([sprout_reenroll_required]) instead of "returned an invalid message!".

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients/cmd"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// decodeAsCLI decodes reply, handleCmdRun's encoded result, the way the
// CLI does (cmd/imas: TargetedResults, then each result as a CmdRun).
func decodeAsCLI(t *testing.T, reply []byte) map[string]apitypes.CmdRun {
	t.Helper()
	var tr apitypes.TargetedResults
	if err := json.Unmarshal(reply, &tr); err != nil {
		t.Fatalf("decoding the reply: %v", err)
	}
	out := map[string]apitypes.CmdRun{}
	for id, r := range tr.Results {
		jw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		var v apitypes.CmdRun
		if err := json.Unmarshal(jw, &v); err != nil {
			t.Fatalf("%s: decoding the result as the CLI does: %v (%s)", id, err, jw)
		}
		out[id] = v
	}
	return out
}

func TestHandleCmdRun_KeylessRefusalReachesTheCLIAsText(t *testing.T) {
	nc, cleanup := startEmbeddedNATS(t)
	defer cleanup()
	setupNatsAPIPKI(t)
	tenant := pki.CurrentTenantID()
	writeNKey(t, "", "accepted", "web-01", "UKEY_WEB01")
	writeNKey(t, "", "accepted", "keyless-01", "UKEY_KEYLESS")
	cmd.RegisterFarmerNatsConn(tenant, nc)
	defer cmd.UnregisterFarmerNatsConn(tenant)
	setupSealedEnv(t)

	stub := newSealedStubSprout(t, tenant, "web-01")
	stub.answer(t, nc, "imas.sprouts.web-01.cmd.run", payloadbox.PurposeCmdRunRequest, payloadbox.PurposeCmdRunResponse,
		func([]byte) any { return apitypes.CmdRun{Stdout: "ok"} })
	failOnRequest(t, nc, "imas.sprouts.keyless-01.cmd.run")
	nc.Flush()

	res, err := handleCmdRun(tenant, mustJSON(t, apitypes.TargetedAction{
		Target: []pki.KeyManager{{SproutID: "web-01"}, {SproutID: "keyless-01"}},
		Action: apitypes.CmdRun{Command: "uptime", Timeout: time.Second},
	}))
	if err != nil {
		t.Fatal(err)
	}
	reply, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}

	// On the wire: the refusal's text, not {"Op":...,"SproutID":...}.
	var wire struct {
		Results map[string]map[string]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(reply, &wire); err != nil {
		t.Fatal(err)
	}
	var text string
	if err := json.Unmarshal(wire.Results["keyless-01"]["error"], &text); err != nil {
		t.Fatalf("keyless-01's error on the wire is %s, want a string", wire.Results["keyless-01"]["error"])
	}
	want := (&cook.ReenrollRequiredError{Op: "cmd.run", SproutID: "keyless-01"}).Error()
	if text != want {
		t.Errorf("keyless-01's error on the wire %q, want %q", text, want)
	}
	if got := string(wire.Results["web-01"]["error"]); got != "null" {
		t.Errorf("web-01's error on the wire %s, want null", got)
	}

	got := decodeAsCLI(t, reply)
	if r := got["web-01"]; r.Error != nil || r.Stdout != "ok" {
		t.Errorf("web-01: %+v", r)
	}
	keyless := got["keyless-01"]
	if keyless.Error == nil {
		t.Fatal("keyless-01: no error")
	}
	for _, want := range []string{"keyless-01", "re-enroll", "[" + cook.ReenrollRequiredCode + "]"} {
		if !strings.Contains(keyless.Error.Error(), want) {
			t.Errorf("keyless-01: error %q doesn't mention %q", keyless.Error, want)
		}
	}
}

// A sprout's own error in its sealed reply now decodes on farmer, and
// reaches the CLI as text: in the new form (a string) and in the form an
// older sprout sends (an object, whose message was lost), which farmer
// used to fail to decode altogether.
func TestHandleCmdRun_SproutErrorInTheSealedReplyDecodes(t *testing.T) {
	for name, c := range map[string]struct {
		reply   any
		wantErr string
	}{
		"string": {
			apitypes.CmdRun{ErrCode: -1, Error: errors.New(`exec: "nope": executable file not found in $PATH`)},
			`exec: "nope": executable file not found in $PATH`,
		},
		"older sprout's object": {
			map[string]any{"errcode": -1, "error": map[string]any{"Name": "nope", "Err": map[string]any{}}},
			"message not sent by an older imas version",
		},
	} {
		t.Run(name, func(t *testing.T) {
			nc, cleanup := startEmbeddedNATS(t)
			defer cleanup()
			setupNatsAPIPKI(t)
			tenant := pki.CurrentTenantID()
			writeNKey(t, "", "accepted", "web-01", "UKEY_WEB01")
			cmd.RegisterFarmerNatsConn(tenant, nc)
			defer cmd.UnregisterFarmerNatsConn(tenant)
			setupSealedEnv(t)

			stub := newSealedStubSprout(t, tenant, "web-01")
			stub.answer(t, nc, "imas.sprouts.web-01.cmd.run", payloadbox.PurposeCmdRunRequest, payloadbox.PurposeCmdRunResponse,
				func([]byte) any { return c.reply })
			nc.Flush()

			res, err := handleCmdRun(tenant, mustJSON(t, apitypes.TargetedAction{
				Target: []pki.KeyManager{{SproutID: "web-01"}},
				Action: apitypes.CmdRun{Command: "nope", Timeout: time.Second},
			}))
			if err != nil {
				t.Fatal(err)
			}
			reply, err := json.Marshal(res)
			if err != nil {
				t.Fatal(err)
			}
			r := decodeAsCLI(t, reply)["web-01"]
			if r.ErrCode != -1 || r.Error == nil || !strings.Contains(r.Error.Error(), c.wantErr) {
				t.Errorf("web-01: errcode %d, error %v, want -1 and %q", r.ErrCode, r.Error, c.wantErr)
			}
		})
	}
}
