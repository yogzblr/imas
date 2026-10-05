package apitypes

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/cook"
)

// A CmdRun's Error goes on the wire as its message: farmer's refusal to
// send to a keyless sprout reaches the CLI with its text and code, where
// encoding/json used to write {"Op":...,"SproutID":...} that no CmdRun
// could decode.
func TestCmdRunErrorTravelsAsItsMessage(t *testing.T) {
	refusal := &cook.ReenrollRequiredError{Op: "cmd.run", SproutID: "web-01"}
	b, err := json.Marshal(CmdRun{Command: "uptime", ErrCode: 0, Error: refusal})
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	var msg string
	if err := json.Unmarshal(raw["error"], &msg); err != nil {
		t.Fatalf("error on the wire is %s, want a string", raw["error"])
	}
	if msg != refusal.Error() {
		t.Errorf("error on the wire %q, want %q", msg, refusal.Error())
	}
	if string(raw["command"]) != `"uptime"` {
		t.Errorf("command on the wire %s", raw["command"])
	}

	var got CmdRun
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Error == nil || got.Error.Error() != refusal.Error() {
		t.Errorf("decoded error %v, want %q", got.Error, refusal.Error())
	}
	if !strings.Contains(got.Error.Error(), "["+cook.ReenrollRequiredCode+"]") {
		t.Errorf("decoded error %q lost the code", got.Error)
	}
	if got.Command != "uptime" {
		t.Errorf("decoded command %q", got.Command)
	}
}

func TestCmdRunNoErrorIsNull(t *testing.T) {
	b, err := json.Marshal(CmdRun{Stdout: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	// null, as before: an older CLI decodes it.
	if !strings.Contains(string(b), `"error":null`) {
		t.Errorf("wire form %s, want \"error\":null", b)
	}
	var got CmdRun
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Error != nil || got.Stdout != "ok" {
		t.Errorf("decoded %+v", got)
	}
}

// What an older farmer or sprout wrote still decodes: null as no error,
// an object as an error whose message was lost, and a missing key leaves
// Error alone.
func TestCmdRunDecodesLegacyErrors(t *testing.T) {
	for name, c := range map[string]struct {
		in      string
		wantErr error
	}{
		"null":                {`{"stdout":"ok","error":null}`, nil},
		"absent":              {`{"stdout":"ok"}`, nil},
		"reenroll object":     {`{"errcode":0,"error":{"Op":"cmd.run","SproutID":"web-01"}}`, errLegacyWireError},
		"exec.Error object":   {`{"errcode":-1,"error":{"Name":"nope","Err":{}}}`, errLegacyWireError},
		"empty object":        {`{"error":{}}`, errLegacyWireError},
		"string":              {`{"error":"boom"}`, errors.New("boom")},
		"empty string kept":   {`{"error":""}`, errors.New("")},
		"unexpected (number)": {`{"error":3}`, errLegacyWireError},
	} {
		var got CmdRun
		if err := json.Unmarshal([]byte(c.in), &got); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		switch {
		case c.wantErr == nil && got.Error != nil:
			t.Errorf("%s: error %v, want nil", name, got.Error)
		case c.wantErr != nil && (got.Error == nil || got.Error.Error() != c.wantErr.Error()):
			t.Errorf("%s: error %v, want %q", name, got.Error, c.wantErr)
		}
	}

	prev := errors.New("kept")
	got := CmdRun{Error: prev}
	if err := json.Unmarshal([]byte(`{"stdout":"x"}`), &got); err != nil {
		t.Fatal(err)
	}
	if got.Error != prev || got.Stdout != "x" {
		t.Errorf("absent key: %+v, want Error kept", got)
	}

	if err := json.Unmarshal([]byte(`{"stdout":3}`), &got); err == nil {
		t.Error("a malformed field decoded without an error")
	}
}

// A CmdRun nested in TargetedResults, as farmer's cmd.run reply carries it,
// decodes back into a CmdRun the way the CLI does.
func TestCmdRunInTargetedResults(t *testing.T) {
	refusal := &cook.ReenrollRequiredError{Op: "cmd.run", SproutID: "web-01"}
	b, err := json.Marshal(TargetedResults{Results: map[string]interface{}{"web-01": CmdRun{Error: refusal}}})
	if err != nil {
		t.Fatal(err)
	}
	var tr TargetedResults
	if err := json.Unmarshal(b, &tr); err != nil {
		t.Fatal(err)
	}
	jw, _ := json.Marshal(tr.Results["web-01"])
	var got CmdRun
	if err := json.Unmarshal(jw, &got); err != nil {
		t.Fatalf("decoding the result as the CLI does: %v", err)
	}
	if got.Error == nil || got.Error.Error() != refusal.Error() {
		t.Errorf("error %v, want %q", got.Error, refusal.Error())
	}
}

func TestCmdCookErrorsTravelAsMessages(t *testing.T) {
	refusal := &cook.ReenrollRequiredError{Op: "cook", SproutID: "web-01"}
	in := CmdCook{Recipe: "nginx", JID: "jid-1", Errors: map[string]error{"web-01": refusal, "web-02": nil}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"web-02":null`) || !strings.Contains(string(b), cook.ReenrollRequiredCode) {
		t.Errorf("wire form %s", b)
	}
	var got CmdCook
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Recipe != "nginx" || got.JID != "jid-1" {
		t.Errorf("decoded %+v", got)
	}
	if e := got.Errors["web-01"]; e == nil || e.Error() != refusal.Error() {
		t.Errorf("web-01: %v, want %q", e, refusal.Error())
	}
	if e, ok := got.Errors["web-02"]; !ok || e != nil {
		t.Errorf("web-02: %v (present %t), want nil", e, ok)
	}

	b, err = json.Marshal(CmdCook{JID: "jid-2"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"errors":null`) {
		t.Errorf("no errors: wire form %s, want \"errors\":null", b)
	}

	var legacy CmdCook
	if err := json.Unmarshal([]byte(`{"jid":"j","errors":{"web-01":{"Op":"cook","SproutID":"web-01"}}}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Errors["web-01"] != errLegacyWireError {
		t.Errorf("legacy object: %v", legacy.Errors["web-01"])
	}
}

// Inline is what the CLI prints for an error in --output json mode, and
// what farmer's pki handlers reply with: its Error goes out as the message,
// where encoding/json used to write "error":{}.
func TestInlineErrorTravelsAsItsMessage(t *testing.T) {
	b, err := json.Marshal(Inline{Success: false, Error: errors.New("boom")})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"success":false,"error":"boom"}` {
		t.Errorf("wire form %s", b)
	}
	var got Inline
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Success || got.Error == nil || got.Error.Error() != "boom" {
		t.Errorf("decoded %+v", got)
	}

	b, err = json.Marshal(Inline{Success: true})
	if err != nil {
		t.Fatal(err)
	}
	// null, as before: an older CLI decodes it.
	if string(b) != `{"success":true,"error":null}` {
		t.Errorf("no error: wire form %s", b)
	}
}

func TestInlineDecodes(t *testing.T) {
	for name, c := range map[string]struct {
		in          string
		wantSuccess bool
		wantErr     error
	}{
		"string":       {`{"success":false,"error":"boom"}`, false, errors.New("boom")},
		"null":         {`{"success":true,"error":null}`, true, nil},
		"absent":       {`{"success":true}`, true, nil},
		"empty object": {`{"success":false,"error":{}}`, false, errLegacyWireError},
	} {
		var got Inline
		if err := json.Unmarshal([]byte(c.in), &got); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.Success != c.wantSuccess {
			t.Errorf("%s: success %t, want %t", name, got.Success, c.wantSuccess)
		}
		switch {
		case c.wantErr == nil && got.Error != nil:
			t.Errorf("%s: error %v, want nil", name, got.Error)
		case c.wantErr != nil && (got.Error == nil || got.Error.Error() != c.wantErr.Error()):
			t.Errorf("%s: error %v, want %q", name, got.Error, c.wantErr)
		}
	}

	prev := errors.New("kept")
	got := Inline{Error: prev}
	if err := json.Unmarshal([]byte(`{"success":true}`), &got); err != nil {
		t.Fatal(err)
	}
	if got.Error != prev || !got.Success {
		t.Errorf("absent key: %+v, want Error kept", got)
	}

	if err := json.Unmarshal([]byte(`{"success":"yes"}`), &got); err == nil {
		t.Error("a malformed field decoded without an error")
	}
}

func TestPingPongErrorTravelsAsItsMessage(t *testing.T) {
	b, err := json.Marshal(PingPong{Ping: true, Error: errors.New("boom")})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"ping":true,"pong":false,"error":"boom"}` {
		t.Errorf("wire form %s", b)
	}
	var got PingPong
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Ping || got.Pong || got.Error == nil || got.Error.Error() != "boom" {
		t.Errorf("decoded %+v", got)
	}

	b, err = json.Marshal(PingPong{Ping: true, Pong: true})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"ping":true,"pong":true,"error":null}` {
		t.Errorf("no error: wire form %s", b)
	}
}

func TestPingPongDecodes(t *testing.T) {
	for name, c := range map[string]struct {
		in       string
		wantPong bool
		wantErr  error
	}{
		"string":       {`{"ping":true,"pong":false,"error":"boom"}`, false, errors.New("boom")},
		"null":         {`{"ping":true,"pong":true,"error":null}`, true, nil},
		"absent":       {`{"ping":true,"pong":true}`, true, nil},
		"empty object": {`{"ping":true,"pong":false,"error":{}}`, false, errLegacyWireError},
	} {
		var got PingPong
		if err := json.Unmarshal([]byte(c.in), &got); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !got.Ping || got.Pong != c.wantPong {
			t.Errorf("%s: decoded %+v", name, got)
		}
		switch {
		case c.wantErr == nil && got.Error != nil:
			t.Errorf("%s: error %v, want nil", name, got.Error)
		case c.wantErr != nil && (got.Error == nil || got.Error.Error() != c.wantErr.Error()):
			t.Errorf("%s: error %v, want %q", name, got.Error, c.wantErr)
		}
	}

	prev := errors.New("kept")
	got := PingPong{Error: prev}
	if err := json.Unmarshal([]byte(`{"pong":true}`), &got); err != nil {
		t.Fatal(err)
	}
	if got.Error != prev || !got.Pong {
		t.Errorf("absent key: %+v, want Error kept", got)
	}

	if err := json.Unmarshal([]byte(`{"pong":"yes"}`), &got); err == nil {
		t.Error("a malformed field decoded without an error")
	}
}
