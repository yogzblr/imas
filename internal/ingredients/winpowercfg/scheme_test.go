package winpowercfg

import (
	"context"
	"testing"
	"time"
)

const activeOut = "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)"

func TestSameScheme(t *testing.T) {
	for _, name := range []string{
		"381b4222-f694-41f0-9685-ff5bb260df2e",
		"381B4222-F694-41F0-9685-FF5BB260DF2E",
		"{381b4222-f694-41f0-9685-ff5bb260df2e}",
		"SCHEME_BALANCED",
		"scheme_balanced",
	} {
		if !sameScheme("381b4222-f694-41f0-9685-ff5bb260df2e", name) {
			t.Errorf("%q should match the active Balanced scheme", name)
		}
	}
	for _, name := range []string{"SCHEME_MIN", "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"} {
		if sameScheme("381b4222-f694-41f0-9685-ff5bb260df2e", name) {
			t.Errorf("%q must not match Balanced", name)
		}
	}
	if sameScheme("", "") {
		t.Error("no active GUID matches nothing")
	}
}

func TestActiveSchemeIdempotentForUpperCaseGUID(t *testing.T) {
	var calls [][]string
	orig := runCLI
	runCLI = func(_ context.Context, _ string, args []string, _ time.Duration) (string, error) {
		calls = append(calls, args)
		return activeOut, nil
	}
	t.Cleanup(func() { runCLI = orig })
	c, err := (Scheme{}).Parse("id1", methodActiveScheme, map[string]interface{}{"name": "381B4222-F694-41F0-9685-FF5BB260DF2E"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Apply(context.Background())
	if err != nil || res.Changed || len(calls) != 1 {
		t.Fatalf("res=%+v err=%v calls=%v", res, err, calls)
	}
}
