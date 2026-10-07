package ingredients

import "testing"

func TestMatcher(t *testing.T) {
	type q struct {
		path []string
		want bool
	}
	for _, tc := range []struct {
		pattern string
		qs      []q
	}{
		{"", []q{{[]string{"TestIngredients", "I.a.b", "t1-ubuntu"}, true}}},
		// run.sh's tier pattern.
		{"^Test(?:Ingredients|Lifecycle)", []q{
			{[]string{"TestIngredients", "I.a.b", "t1-ubuntu"}, true},
			{[]string{"TestCoreC1_x"}, false},
		}},
		// run.sh's pattern for ingredient ids (uatreport RunPattern).
		{`^TestIngredients$/(?:I\.file\.content|I\.pkg\.installed)(?:$|[^a-z0-9_.])`, []q{
			{[]string{"TestIngredients", "I.file.content", "t1-alma"}, true},
			{[]string{"TestIngredients", "I.pkg.installed"}, true},
			{[]string{"TestIngredients", "I.file.content_x"}, false},
			{[]string{"TestIngredients", "I.file.contents"}, false},
			{[]string{"TestIngredientsCoverage"}, false},
		}},
		// a hand-written selection down to one sprout, with alternatives.
		{`TestIngredients/I\.cron\.present/t1-alma|TestIngredients/I\.cmd\.run`, []q{
			{[]string{"TestIngredients", "I.cron.present", "t1-alma"}, true},
			{[]string{"TestIngredients", "I.cron.present", "t1-ubuntu"}, false},
			{[]string{"TestIngredients", "I.cmd.run", "t2-windows"}, true},
		}},
		// brackets keep their slashes and bars.
		{`TestIngredients/[a|/]x`, []q{
			{[]string{"TestIngredients", "bx"}, false},
			{[]string{"TestIngredients", "I|x"}, true},
			{[]string{"TestIngredients", "/x"}, true},
		}},
	} {
		m, err := NewMatcher(tc.pattern)
		if err != nil {
			t.Fatalf("%q: %v", tc.pattern, err)
		}
		for _, x := range tc.qs {
			if got := m.Match(x.path...); got != x.want {
				t.Errorf("%q matching %v: %v, want %v", tc.pattern, x.path, got, x.want)
			}
		}
	}
}

func TestMatcherSkip(t *testing.T) {
	m, err := NewMatcher(`TestIngredients/I\.pkg\.`)
	if err != nil {
		t.Fatal(err)
	}
	if !m.MatchSkip("TestIngredients", "I.pkg.held", "t1-alma") {
		t.Error("a deeper path under a skipped case is skipped")
	}
	if m.MatchSkip("TestIngredients") {
		t.Error("the parent of a skip pattern is not skipped")
	}
	if m.MatchSkip("TestIngredients", "I.file.content", "t1-alma") {
		t.Error("another case is not skipped")
	}
	empty, _ := NewMatcher("")
	if empty.MatchSkip("TestIngredients", "I.a.b") {
		t.Error("an empty skip pattern skips nothing")
	}
}
