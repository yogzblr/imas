package harness

import (
	"fmt"
	"strings"
)

// The recipes of RB1 (S4, security review B4): parts that each stay inside
// every per-render limit of farmer's recipe templates (internal/cook), and
// two main recipes including them, one whose cook runs out of the per-cook
// budget and one whose cook stays inside it. TestRB1RecipesAgainstCook
// renders this exact text with the cook package's own limits.

// RB1PartRecipe is one part: nine ranges over the 1000 characters of
// printf "%01000d" 0 (farmer caps a printf width at 1000), 9000 range
// iterations in one render, under the 10000 per render
// (cook.DefaultMaxRangeIterations). A cook renders each recipe twice (once
// to find its includes, once to build its steps), so a part costs the cook
// 18000 of its 100000 (cook.DefaultCookMaxRangeIterations).
var RB1PartRecipe = strings.Repeat(`{{ range split (printf "%01000d" 0) "" }}{{ end }}`, 9) + "steps: {}\n"

// RB1 part counts: the over-budget main recipe includes RB1OverParts parts
// (7 x 18000 = 126000 iterations, over the per-cook 100000), the
// inside-budget one RB1InParts (2 x 18000 = 36000).
const (
	RB1PartIterations = 9 * 1000
	RB1OverParts      = 7
	RB1InParts        = 2
)

// RB1MainRecipe is a main recipe including includes, with one step that
// writes text to file in the sprout's temporary directory (C:\Windows\Temp
// on Windows, /var/tmp otherwise).
func RB1MainRecipe(includes []string, file, text string) string {
	return "include:\n  - " + strings.Join(includes, "\n  - ") + fmt.Sprintf(`
steps:
  uat rb1 marker:
    file.content:
{{- if eq (props "os") "windows" }}
      - name: 'C:\Windows\Temp\%[1]s'
{{- else }}
      - name: /var/tmp/%[1]s
{{- end }}
      - text: "%[2]s"
`, file, text)
}
