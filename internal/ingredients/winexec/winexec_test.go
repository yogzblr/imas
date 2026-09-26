package winexec

import (
	"context"
	"testing"
	"time"
)

func TestParseTimeoutDefault(t *testing.T) {
	d, err := ParseTimeout("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != DefaultTimeout {
		t.Errorf("expected DefaultTimeout, got %v", d)
	}
}

func TestParseTimeoutValid(t *testing.T) {
	d, err := ParseTimeout("5s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 5*time.Second {
		t.Errorf("expected 5s, got %v", d)
	}
}

func TestParseTimeoutInvalid(t *testing.T) {
	if _, err := ParseTimeout("not-a-duration"); err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestStringParam(t *testing.T) {
	params := map[string]interface{}{"name": "value", "wrong_type": 42}
	if v, ok := StringParam(params, "name"); !ok || v != "value" {
		t.Errorf("expected (value, true), got (%q, %v)", v, ok)
	}
	if _, ok := StringParam(params, "missing"); ok {
		t.Error("expected ok=false for missing key")
	}
	if _, ok := StringParam(params, "wrong_type"); ok {
		t.Error("expected ok=false for wrong type")
	}
}

func TestBoolParam(t *testing.T) {
	params := map[string]interface{}{"flag": true, "wrong_type": "yes"}
	if !BoolParam(params, "flag", false) {
		t.Error("expected true")
	}
	if !BoolParam(params, "missing", true) {
		t.Error("expected default true for missing key")
	}
	if BoolParam(params, "wrong_type", false) {
		t.Error("expected default false for wrong type")
	}
}

func TestStringSliceParam(t *testing.T) {
	params := map[string]interface{}{"servers": []string{"a", "b"}, "wrong_type": "a"}
	v, ok := StringSliceParam(params, "servers")
	if !ok || len(v) != 2 {
		t.Errorf("expected 2-element slice, got %v, ok=%v", v, ok)
	}
	if _, ok := StringSliceParam(params, "missing"); ok {
		t.Error("expected ok=false for missing key")
	}
	if _, ok := StringSliceParam(params, "wrong_type"); ok {
		t.Error("expected ok=false for wrong type")
	}
}

func TestStringParamOr(t *testing.T) {
	params := map[string]interface{}{"name": "value"}
	if got := StringParamOr(params, "name", "default"); got != "value" {
		t.Errorf("expected value, got %q", got)
	}
	if got := StringParamOr(params, "missing", "default"); got != "default" {
		t.Errorf("expected default, got %q", got)
	}
}

func TestPSQuote(t *testing.T) {
	if got := PSQuote("simple"); got != "'simple'" {
		t.Errorf("expected 'simple', got %q", got)
	}
	if got := PSQuote("it's"); got != "'it''s'" {
		t.Errorf("expected escaped quote, got %q", got)
	}
}

func TestPSBool(t *testing.T) {
	if PSBool(true) != "$true" {
		t.Error("expected $true")
	}
	if PSBool(false) != "$false" {
		t.Error("expected $false")
	}
}

func TestRunCLINonexistentBinary(t *testing.T) {
	_, err := RunCLI(context.Background(), "imas-definitely-not-a-real-binary", nil, 2*time.Second)
	if err == nil {
		t.Error("expected error for nonexistent binary")
	}
}
