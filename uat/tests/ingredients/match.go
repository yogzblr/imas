package ingredients

import (
	"regexp"
	"strings"
)

// The runner does its work in one worker per sprout, ahead of the
// subtests that report it (so the work on one sprout keeps its order
// while sprouts run in parallel, whatever -test.parallel is). It must
// therefore know up front which subtests go test will run. Matcher
// applies -test.run and -test.skip the way the testing package does:
// the pattern is split into alternatives at unbracketed '|' and each
// alternative into one regexp per subtest level at unbracketed '/'; a
// name matches a level's regexp anywhere in it, and levels past the
// pattern's last element always match.

// Matcher is a parsed -test.run or -test.skip pattern.
type Matcher struct {
	alts [][]*regexp.Regexp
}

// NewMatcher parses a pattern. An empty pattern matches everything.
func NewMatcher(pattern string) (*Matcher, error) {
	m := &Matcher{}
	if pattern == "" {
		return m, nil
	}
	for _, alt := range splitRegexp(pattern) {
		var levels []*regexp.Regexp
		for _, el := range alt {
			re, err := regexp.Compile(el)
			if err != nil {
				return nil, err
			}
			levels = append(levels, re)
		}
		m.alts = append(m.alts, levels)
	}
	return m, nil
}

// Empty reports whether the pattern was empty.
func (m *Matcher) Empty() bool { return len(m.alts) == 0 }

// Match reports whether a test path (top-level name, then subtest names)
// matches. For -test.run, a path matches when every level present
// matches (a prefix of a longer pattern is "partial" and still runs).
func (m *Matcher) Match(path ...string) bool {
	if len(m.alts) == 0 {
		return true
	}
	for _, alt := range m.alts {
		ok := true
		for i, name := range path {
			if i >= len(alt) {
				break
			}
			if !alt[i].MatchString(rewrite(name)) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// MatchSkip reports whether a -test.skip pattern skips the path: some
// alternative matches every one of its levels, and the path is at least
// as deep as that alternative.
func (m *Matcher) MatchSkip(path ...string) bool {
	for _, alt := range m.alts {
		if len(path) < len(alt) {
			continue
		}
		ok := true
		for i, re := range alt {
			if !re.MatchString(rewrite(path[i])) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// rewrite is the testing package's subtest name rewriting for the names
// this runner uses: spaces become underscores.
func rewrite(s string) string { return strings.ReplaceAll(s, " ", "_") }

// splitRegexp splits a -run pattern as the testing package does.
func splitRegexp(s string) [][]string {
	var alts [][]string
	var cur []string
	cs, cp := 0, 0
	for i := 0; i < len(s); {
		switch s[i] {
		case '[':
			cs++
		case ']':
			if cs--; cs < 0 {
				cs = 0
			}
		case '(':
			if cs == 0 {
				cp++
			}
		case ')':
			if cs == 0 {
				cp--
			}
		case '\\':
			i++
		case '/':
			if cs == 0 && cp == 0 {
				cur = append(cur, s[:i])
				s = s[i+1:]
				i = 0
				continue
			}
		case '|':
			if cs == 0 && cp == 0 {
				cur = append(cur, s[:i])
				s = s[i+1:]
				i = 0
				alts = append(alts, cur)
				cur = nil
				continue
			}
		}
		i++
	}
	cur = append(cur, s)
	alts = append(alts, cur)
	return alts
}
