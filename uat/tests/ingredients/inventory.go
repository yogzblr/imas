package ingredients

import (
	"fmt"
	"strings"
)

// RenderInventory writes uat/cases/INVENTORY.md from the registry. The
// unit test TestInventoryUpToDate fails when the file differs, and
// rewrites it with -update.
func RenderInventory(reg *Registry) []byte {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	w("<!-- generated from the source by uat/tests/ingredients (RenderInventory); do not edit by hand.\n")
	w("     Regenerate: go test ./uat/tests/ingredients -run TestInventoryUpToDate -update -->\n")
	w("# Ingredient inventory (UAT.7)\n\n")
	w("Every ingredient method a sprout registers, read from the code: the packages\n")
	w("`cmd/sprout` imports for each GOOS (`include.go`, `include_linux.go`,\n")
	w("`include_windows.go`, and what they import in turn), every\n")
	w("`ingredients.RegisterAllMethods(T{})` in their `init` functions, and `T`'s\n")
	w("`Methods()` and `PropertiesForMethod()`. Build constraints are applied per\n")
	w("GOOS with CGO off, as the sprout is built. Linux means the Ubuntu 24.04 and\n")
	w("AlmaLinux 9 sprouts of the UAT gate; Windows means Windows Server 2022 Core.\n\n")
	linux, windows, both := 0, 0, 0
	ings := map[string]bool{}
	for _, m := range reg.Methods {
		ings[m.Ingredient] = true
		l, wi := has(m.GOOS, GOOSLinux), has(m.GOOS, GOOSWindows)
		switch {
		case l && wi:
			both++
		case l:
			linux++
		case wi:
			windows++
		}
	}
	w("**%d methods** in %d ingredients: %d on both platforms, %d on Linux only, %d on Windows only.\n", len(reg.Methods), len(ings), both, linux, windows)
	w("Each has a case file `uat/cases/<ingredient>/<method>.yaml` (format: [README.md](README.md)).\n\n")
	w("Properties: `*` marks a required one. A note says when they couldn't be read\n")
	w("from the source or look wrong.\n\n")

	cur := ""
	for _, m := range reg.Methods {
		if m.Ingredient != cur {
			cur = m.Ingredient
			w("\n## %s\n\n", cur)
			w("Package `%s`, type `%s`.\n\n", strings.TrimPrefix(m.Package, ModulePath+"/"), m.Type)
			w("| Case id | OS | Properties |\n|---|---|---|\n")
		}
		w("| `%s` | %s | %s |\n", m.ID(), osLabel(m.GOOS), propsCell(m))
	}

	if len(reg.Unreachable) > 0 {
		w("\n## Registered by a package no sprout imports\n\n")
		w("These packages call `RegisterAllMethods`, but `cmd/sprout` doesn't import them on\n")
		w("any platform, so a recipe naming them fails with \"unknown ingredient\" on every\n")
		w("sprout. Their cases are skips that say so (a finding for the owner).\n\n")
		w("| Case id | Built for | Package | Properties |\n|---|---|---|---|\n")
		for _, m := range reg.Unreachable {
			w("| `%s` | %s | `%s` | %s |\n", m.ID(), osLabel(m.GOOS), strings.TrimPrefix(m.Package, ModulePath+"/"), propsCell(m))
		}
	}

	if len(reg.Backends) > 0 {
		w("\n## Registries the ingredients delegate to\n\n")
		w("Not methods, but registered the same way: the `sdb://` secret backends a step's\n")
		w("`secrets:` resolve through, and the protocols a file `source` is fetched with.\n\n")
		w("| Registry | Name | OS | Package |\n|---|---|---|---|\n")
		for _, bk := range reg.Backends {
			w("| %s | `%s` | %s | `%s` |\n", bk.Registry, bk.Name, osLabel(bk.GOOS), strings.TrimPrefix(bk.Package, ModulePath+"/"))
		}
	}
	return []byte(b.String())
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func osLabel(goos []string) string {
	var parts []string
	for _, g := range goos {
		switch g {
		case GOOSLinux:
			parts = append(parts, "Linux (ubuntu, alma)")
		case GOOSWindows:
			parts = append(parts, "Windows")
		default:
			parts = append(parts, g)
		}
	}
	return strings.Join(parts, ", ")
}

func propsCell(m Method) string {
	var parts []string
	for _, p := range m.Props {
		s := "`" + p.Key + "`"
		if p.Required {
			s += "*"
		}
		if p.Type != "" {
			s += " " + p.Type
		}
		parts = append(parts, s)
	}
	cell := strings.Join(parts, ", ")
	if cell == "" {
		cell = "none declared"
	}
	if m.PropsNote != "" {
		cell += " (note: " + strings.ReplaceAll(m.PropsNote, "|", "\\|") + ")"
	}
	return cell
}
