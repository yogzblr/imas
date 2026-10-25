package harness

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
)

func TestVMDiagCollectsUpToMaxPerVM(t *testing.T) {
	var calls [][]string
	d := &VMDiag{Hook: "diagnostics.sh", Dir: "/r/diagnostics", Max: 2, Exec: func(_ context.Context, args []string) error {
		calls = append(calls, args)
		return nil
	}}
	ctx := context.Background()
	out, err := d.Collect(ctx, "t1-win", "ace3f2c3-0862-4541-a9b9-4f38daa8b556", "bad jid;rm -rf /")
	if err != nil || out != filepath.Join("/r/diagnostics", "t1-win") {
		t.Fatalf("Collect = %q, %v", out, err)
	}
	if want := []string{"vm", "/r/diagnostics/t1-win", "t1-win", "ace3f2c3-0862-4541-a9b9-4f38daa8b556"}; !reflect.DeepEqual(calls[0], want) {
		t.Errorf("args = %q, want %q (a malformed job id is dropped)", calls[0], want)
	}
	d.Collect(ctx, "t1-win")
	if out, _ := d.Collect(ctx, "t1-win"); out != "" || len(calls) != 2 {
		t.Errorf("a third collection for t1-win: out %q, %d calls; want none past Max", out, len(calls))
	}
	if out, _ := d.Collect(ctx, "t1-alma"); out == "" || len(calls) != 3 {
		t.Errorf("another VM has its own quota: out %q, %d calls", out, len(calls))
	}
	if out, _ := d.Collect(ctx, "../etc"); out != "" {
		t.Errorf("a VM name that is a path is refused: %q", out)
	}
	var nilD *VMDiag
	if out, err := nilD.Collect(ctx, "t1-win"); out != "" || err != nil {
		t.Errorf("a nil VMDiag is a no-op: %q, %v", out, err)
	}
}
