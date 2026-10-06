package ingredients

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite uat/cases/INVENTORY.md from the source")

// TestInventoryUpToDate keeps uat/cases/INVENTORY.md equal to what the
// source registers. Regenerate with:
//
//	go test ./uat/tests/ingredients -run TestInventoryUpToDate -update
func TestInventoryUpToDate(t *testing.T) {
	root, err := FindRoot()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := LoadRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	want := RenderInventory(reg)
	path := filepath.Join(root, "uat", "cases", "INVENTORY.md")
	if *update {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is out of date with the ingredient registry; run go test ./uat/tests/ingredients -run TestInventoryUpToDate -update", path)
	}
}

func TestRenderInventory(t *testing.T) {
	reg := fakeRegistry()
	fc, _ := reg.Get("I.file.content")
	fc.Props = []Prop{{Key: "name", Type: "string", Required: true}, {Key: "text", Type: "[]string"}}
	fc.PropsNote = "a | b"
	out := string(RenderInventory(reg))
	for _, want := range []string{
		"**3 methods** in 3 ingredients: 1 on both platforms, 1 on Linux only, 1 on Windows only.",
		"| `I.cron.present` | Linux (ubuntu, alma) | none declared |",
		"| `I.file.content` | Linux (ubuntu, alma), Windows |",
		"`name`* string, `text` []string (note: a \\| b)",
		"## Registered by a package no sprout imports",
		"| `I.win_y.off` | Windows | `internal/ingredients/winy` |",
		"| sdb | `openbao` | Linux (ubuntu, alma) |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("inventory lacks %q:\n%s", want, out)
		}
	}
}
