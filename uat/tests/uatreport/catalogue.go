package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Tiers, in the order the plan lists them.
var tiers = []string{"smoke", "core", "resilience", "ingredients", "lifecycle"}

// prefixOfTier is the test-function prefix of each tier's own scenarios
// (plan section 4h, Scenario catalogue).
var prefixOfTier = map[string]string{
	"smoke":       "Smoke",
	"core":        "Core",
	"resilience":  "Resilience",
	"ingredients": "Ingredients",
	"lifecycle":   "Lifecycle",
}

// ingredientWildcard is the catalogue row standing for every I.name.method
// id: UAT.7's cases, whose ids aren't known statically.
const ingredientWildcard = "I.*"

// Scenario is one row of catalogue.tsv.
type Scenario struct {
	ID    string
	Tiers []string
	Title string
	Owner string
}

// InTier reports whether the scenario belongs to tier ("all" holds every one).
func (s Scenario) InTier(tier string) bool {
	if tier == "all" {
		return true
	}
	for _, t := range s.Tiers {
		if t == tier {
			return true
		}
	}
	return false
}

// Prefix is the test-function prefix of the scenario: its first tier's,
// so a smoke-and-core scenario is a TestSmoke function.
func (s Scenario) Prefix() string { return prefixOfTier[s.Tiers[0]] }

// Catalogue is catalogue.tsv, in file order.
type Catalogue struct {
	Scenarios []Scenario
	byID      map[string]Scenario
}

var staticID = regexp.MustCompile(`^[A-Z][0-9]+$`)

// IngredientID matches an ingredient conformance id, I.<name>.<method>.
var IngredientID = regexp.MustCompile(`^I\.[a-z0-9_]+(\.[a-z0-9_]+)+$`)

// ReadCatalogue parses catalogue.tsv: tab-separated id, tiers (comma
// separated), title and owning brief; # starts a comment line.
func ReadCatalogue(r io.Reader) (*Catalogue, error) {
	c := &Catalogue{byID: map[string]Scenario{}}
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(text) == "" || strings.HasPrefix(strings.TrimSpace(text), "#") {
			continue
		}
		f := strings.Split(text, "\t")
		if len(f) != 4 {
			return nil, fmt.Errorf("catalogue line %d: want 4 tab-separated fields, got %d", line, len(f))
		}
		s := Scenario{ID: strings.TrimSpace(f[0]), Title: strings.TrimSpace(f[2]), Owner: strings.TrimSpace(f[3])}
		if !staticID.MatchString(s.ID) && s.ID != ingredientWildcard {
			return nil, fmt.Errorf("catalogue line %d: bad id %q", line, s.ID)
		}
		for _, t := range strings.Split(f[1], ",") {
			t = strings.TrimSpace(t)
			if _, ok := prefixOfTier[t]; !ok {
				return nil, fmt.Errorf("catalogue line %d: unknown tier %q", line, t)
			}
			s.Tiers = append(s.Tiers, t)
		}
		if _, dup := c.byID[s.ID]; dup {
			return nil, fmt.Errorf("catalogue line %d: duplicate id %s", line, s.ID)
		}
		c.byID[s.ID] = s
		c.Scenarios = append(c.Scenarios, s)
	}
	return c, sc.Err()
}

// LoadCatalogue reads a catalogue file.
func LoadCatalogue(path string) (*Catalogue, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadCatalogue(f)
}

// Get returns a scenario by id.
func (c *Catalogue) Get(id string) (Scenario, bool) {
	s, ok := c.byID[id]
	return s, ok
}

// InTier lists the scenarios of a tier, in file order.
func (c *Catalogue) InTier(tier string) []Scenario {
	var out []Scenario
	for _, s := range c.Scenarios {
		if s.InTier(tier) {
			out = append(out, s)
		}
	}
	return out
}

// ValidTier reports whether tier is a tier name or "all".
func ValidTier(tier string) bool {
	_, ok := prefixOfTier[tier]
	return ok || tier == "all"
}

// Selection is what a run asks for: a tier, and optionally ids in it.
type Selection struct {
	Tier string
	// Static are the catalogue ids asked for; Ingredient the I. ids.
	Static     []Scenario
	Ingredient []string
	// All is true when no ids were given: the whole tier.
	All bool
}

// Select validates a tier and ids against the catalogue.
func (c *Catalogue) Select(tier string, ids []string) (*Selection, error) {
	if !ValidTier(tier) {
		return nil, fmt.Errorf("unknown tier %q: want smoke, core, resilience, ingredients, lifecycle or all", tier)
	}
	sel := &Selection{Tier: tier, All: len(ids) == 0}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		if IngredientID.MatchString(id) {
			if tier != "ingredients" && tier != "all" {
				return nil, fmt.Errorf("%s is an ingredient id, not in tier %s", id, tier)
			}
			sel.Ingredient = append(sel.Ingredient, id)
			continue
		}
		s, ok := c.Get(id)
		if !ok || s.ID == ingredientWildcard {
			return nil, fmt.Errorf("unknown scenario id %q (not in the catalogue)", id)
		}
		if !s.InTier(tier) {
			return nil, fmt.Errorf("scenario %s is in tier %s, not %s", id, strings.Join(s.Tiers, ", "), tier)
		}
		sel.Static = append(sel.Static, s)
	}
	if len(sel.Static) > 0 && len(sel.Ingredient) > 0 {
		return nil, fmt.Errorf("give ingredient ids (I.name.method) and other ids in separate runs: go test -run can't select both in one pattern")
	}
	return sel, nil
}

// Expected lists the static scenarios the run must account for.
func (c *Catalogue) Expected(sel *Selection) []Scenario {
	if !sel.All {
		return sel.Static
	}
	var out []Scenario
	for _, s := range c.InTier(sel.Tier) {
		if s.ID != ingredientWildcard {
			out = append(out, s)
		}
	}
	return out
}

// ExpectsIngredients reports whether the run must include ingredient
// conformance tests.
func (c *Catalogue) ExpectsIngredients(sel *Selection) bool {
	if len(sel.Ingredient) > 0 {
		return true
	}
	if !sel.All {
		return false
	}
	s, ok := c.Get(ingredientWildcard)
	return ok && s.InTier(sel.Tier)
}

// Prefixes are the test-function prefixes a selection runs.
func (c *Catalogue) Prefixes(sel *Selection) []string {
	set := map[string]bool{}
	switch {
	case len(sel.Ingredient) > 0:
		set["Ingredients"] = true
	case !sel.All:
		for _, s := range sel.Static {
			set[s.Prefix()] = true
		}
	default:
		for _, s := range c.InTier(sel.Tier) {
			set[s.Prefix()] = true
		}
		if p, ok := prefixOfTier[sel.Tier]; ok {
			set[p] = true
		}
	}
	var out []string
	for _, t := range tiers {
		if set[prefixOfTier[t]] {
			out = append(out, prefixOfTier[t])
		}
	}
	return out
}

// RunPattern is the go test -run pattern of a selection.
func (c *Catalogue) RunPattern(sel *Selection) string {
	switch {
	case len(sel.Ingredient) > 0:
		var alts []string
		for _, id := range sel.Ingredient {
			alts = append(alts, regexp.QuoteMeta(id))
		}
		sort.Strings(alts)
		return "^TestIngredients$/(?:" + strings.Join(alts, "|") + ")(?:$|[^a-z0-9_.])"
	case !sel.All:
		var alts []string
		for _, s := range sel.Static {
			alts = append(alts, s.Prefix()+s.ID)
		}
		return "^Test(?:" + strings.Join(alts, "|") + ")_"
	default:
		return "^Test(?:" + strings.Join(c.Prefixes(sel), "|") + ")"
	}
}
