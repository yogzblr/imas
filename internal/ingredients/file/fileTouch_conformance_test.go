package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// UAT.9: findings from reading file.touch for the UAT gate
// (uat/cases/file/touch.yaml): test mode created a missing file, and a real
// run reported a change although the timestamps already matched.

func TestTouchTestModeDoesNotCreate(t *testing.T) {
	name := filepath.Join(t.TempDir(), "absent")
	f := File{id: "t", method: "touch", params: map[string]interface{}{
		"name": name, "atime": "2024-01-02T03:04:05Z", "mtime": "2024-01-02T03:04:05Z",
	}}
	res, err := f.touch(context.Background(), true)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("test mode on a missing file: %+v, %v; want a change", res, err)
	}
	if _, err := os.Stat(name); err == nil {
		t.Error("test mode created the file")
	}
}

func TestTouchSecondRunChangesNothing(t *testing.T) {
	name := filepath.Join(t.TempDir(), "file")
	f := File{id: "t", method: "touch", params: map[string]interface{}{
		"name": name, "atime": "2024-01-02T03:04:05Z", "mtime": "2024-01-02T03:04:05Z",
	}}
	ctx := context.Background()
	res, err := f.touch(ctx, false)
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("first run: %+v, %v", res, err)
	}
	want := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	if st, _ := os.Stat(name); !st.ModTime().Equal(want) {
		t.Fatalf("mtime %v, want %v", st.ModTime(), want)
	}
	for _, test := range []bool{true, false} {
		res, err = f.touch(ctx, test)
		if err != nil || !res.Succeeded {
			t.Fatalf("second run (test=%v): %+v, %v", test, res, err)
		}
		if res.Changed {
			t.Errorf("second run (test=%v) reports a change although both timestamps match", test)
		}
	}
}

// With no timestamps given, touch sets them to now: that stays a change.
func TestTouchWithoutTimestampsIsAChange(t *testing.T) {
	name := filepath.Join(t.TempDir(), "file")
	f := File{id: "t", method: "touch", params: map[string]interface{}{"name": name}}
	for i := 0; i < 2; i++ {
		res, err := f.touch(context.Background(), false)
		if err != nil || !res.Succeeded || !res.Changed {
			t.Fatalf("run %d: %+v, %v", i, res, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
