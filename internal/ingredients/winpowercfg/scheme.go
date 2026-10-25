package winpowercfg

import (
	"strings"

	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

// Only init (register.go) is Windows-only: powercfg runs through runCLI,
// so the comparison below is unit-tested on every platform.

// runCLI runs powercfg.exe; tests replace it.
var runCLI = winexec.RunCLI

// schemeAliases are the aliases powercfg /setactive accepts for the
// built-in schemes, by the GUID /getactivescheme prints for them.
var schemeAliases = map[string]string{
	"SCHEME_BALANCED": "381b4222-f694-41f0-9685-ff5bb260df2e",
	"SCHEME_MIN":      "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", // High performance
	"SCHEME_MAX":      "a1841308-3541-4fab-bc81-f71556f20b4a", // Power saver
}

// sameScheme reports whether the active scheme's GUID is the one the step
// names. powercfg prints the GUID in lower case; a recipe may name it in
// upper case or by alias, and an exact comparison reported a change on
// every run.
func sameScheme(activeGUID, name string) bool {
	if g, ok := schemeAliases[strings.ToUpper(strings.TrimSpace(name))]; ok {
		name = g
	}
	return activeGUID != "" && strings.EqualFold(strings.TrimSpace(activeGUID), strings.Trim(strings.TrimSpace(name), "{}"))
}
