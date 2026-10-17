package audit

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestIsReadOnly(t *testing.T) {
	readOnly := []string{"version", "sprouts.list", "jobs.list", "auth.login", "auth.whoami"}
	for _, a := range readOnly {
		if !IsReadOnly(a) {
			t.Errorf("IsReadOnly(%q) = false, want true", a)
		}
	}

	writeActions := []string{"cook", "pki.accept", "props.set", "jobs.cancel"}
	for _, a := range writeActions {
		if IsReadOnly(a) {
			t.Errorf("IsReadOnly(%q) = true, want false", a)
		}
	}
}

func TestExtractTargets(t *testing.T) {
	tests := []struct {
		name   string
		params string
		want   []string
	}{
		{
			name:   "sprout_id",
			params: `{"sprout_id":"web-1"}`,
			want:   []string{"web-1"},
		},
		{
			name:   "sprout_ids",
			params: `{"sprout_ids":["web-1","web-2"]}`,
			want:   []string{"web-1", "web-2"},
		},
		{
			name:   "target array",
			params: `{"target":[{"SproutID":"db-1"},{"SproutID":"db-2"}]}`,
			want:   []string{"db-1", "db-2"},
		},
		{
			name:   "empty",
			params: `{}`,
			want:   nil,
		},
		{
			name:   "nil",
			params: "",
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var params json.RawMessage
			if tt.params != "" {
				params = json.RawMessage(tt.params)
			}
			got := extractTargets(params)
			if len(got) != len(tt.want) {
				t.Errorf("extractTargets() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("extractTargets()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// LogAction records the action, its targets and its params, but no user:
// a token in params is neither resolved nor stored (Log masks it). A user's request is
// audited by the sealed router with the user it verified (see
// TestSealedRouterAudit in internal/natsapi).
func TestLogActionWithGlobal(t *testing.T) {
	var buf bytes.Buffer
	SetGlobal(NewLogger(&buf))
	defer SetGlobal(nil)

	params := json.RawMessage(`{"token":"test-token","sprout_id":"web-1","username":"mallory"}`)
	if err := LogAction("pki.accept", params, nil, nil); err != nil {
		t.Fatalf("LogAction: %v", err)
	}

	var got Entry
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.Pubkey != "" || got.RoleName != "" || got.Username != "" {
		t.Errorf("identity from params: pubkey %q role %q username %q, want none", got.Pubkey, got.RoleName, got.Username)
	}
	if got.Action != "pki.accept" {
		t.Errorf("action = %q, want pki.accept", got.Action)
	}
	if !got.Success {
		t.Error("success = false, want true")
	}
	if len(got.Targets) != 1 || got.Targets[0] != "web-1" {
		t.Errorf("targets = %v, want [web-1]", got.Targets)
	}

	var pm map[string]json.RawMessage
	if err := json.Unmarshal(got.Parameters, &pm); err != nil {
		t.Fatalf("parameters %s: %v", got.Parameters, err)
	}
	if string(pm["token"]) != `"[REDACTED]"` || bytes.Contains(buf.Bytes(), []byte("test-token")) {
		t.Errorf("parameters = %s, want token redacted", got.Parameters)
	}
	if string(pm["sprout_id"]) != `"web-1"` {
		t.Errorf("parameters = %s, want sprout_id kept", got.Parameters)
	}
}

func TestLogActionNoGlobal(t *testing.T) {
	SetGlobal(nil)

	// Should silently succeed
	err := LogAction("cook", nil, nil, nil)
	if err != nil {
		t.Fatalf("LogAction with no global: %v", err)
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  Level
	}{
		{"all", LevelAll},
		{"write", LevelWrite},
		{"off", LevelOff},
		{"", LevelWrite},
		{"invalid", LevelWrite},
		{"ALL", LevelWrite}, // case-sensitive
	}

	for _, tt := range tests {
		got := ParseLevel(tt.input)
		if got != tt.want {
			t.Errorf("ParseLevel(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestShouldLog(t *testing.T) {
	tests := []struct {
		level  Level
		action string
		want   bool
	}{
		{LevelAll, "cook", true},
		{LevelAll, "version", true},
		{LevelAll, "sprouts.list", true},
		{LevelWrite, "cook", true},
		{LevelWrite, "pki.accept", true},
		{LevelWrite, "version", false},
		{LevelWrite, "sprouts.list", false},
		{LevelOff, "cook", false},
		{LevelOff, "version", false},
	}

	for _, tt := range tests {
		SetLevel(tt.level)
		got := ShouldLog(tt.action)
		if got != tt.want {
			t.Errorf("ShouldLog(%q) at level %q = %v, want %v",
				tt.action, tt.level, got, tt.want)
		}
	}

	// Restore default
	SetLevel(LevelWrite)
}

func TestSetAndGetLevel(t *testing.T) {
	SetLevel(LevelAll)
	if got := GetLevel(); got != LevelAll {
		t.Errorf("GetLevel() = %q, want %q", got, LevelAll)
	}
	SetLevel(LevelOff)
	if got := GetLevel(); got != LevelOff {
		t.Errorf("GetLevel() = %q, want %q", got, LevelOff)
	}
	// Restore
	SetLevel(LevelWrite)
}

func TestLogActionReadOnlySkipped(t *testing.T) {
	var buf bytes.Buffer
	SetGlobal(NewLogger(&buf))
	defer SetGlobal(nil)

	// Read-only actions should still work via LogAction (the caller
	// in router.go skips them, but LogAction itself doesn't reject them)
	if err := LogAction("version", nil, nil, nil); err != nil {
		t.Fatalf("LogAction: %v", err)
	}
}
