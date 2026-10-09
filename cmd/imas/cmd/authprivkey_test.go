package cmd

import (
	"encoding/json"
	"errors"
	"testing"
)

// `imas auth privkey --output json` must exit 0 when the key was created and
// 1 when it was not (issue #138: it used to exit 1 either way).
func TestPrivkeyJSONResult(t *testing.T) {
	t.Run("success exits 0", func(t *testing.T) {
		out, code := privkeyJSONResult(nil)
		if code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
		var got struct {
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("output %q is not JSON: %v", out, err)
		}
		if !got.Success || got.Error != "" {
			t.Fatalf("got %+v, want success with no error", got)
		}
	})
	t.Run("failure exits 1 and carries the error", func(t *testing.T) {
		out, code := privkeyJSONResult(errors.New("disk full"))
		if code != 1 {
			t.Fatalf("exit code = %d, want 1", code)
		}
		var got struct {
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("output %q is not JSON: %v", out, err)
		}
		if got.Success || got.Error != "disk full" {
			t.Fatalf("got %+v, want failure with the error text", got)
		}
	})
}
