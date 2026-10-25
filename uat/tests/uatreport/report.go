package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Event is one line of go test -json (test2json) output.
type Event struct {
	Action  string  `json:"Action"`
	Package string  `json:"Package"`
	Test    string  `json:"Test"`
	Elapsed float64 `json:"Elapsed"`
	Output  string  `json:"Output"`
}

// node is one test or subtest, or a package (Test empty).
type node struct {
	pkg, name string
	status    string // pass, fail, skip, or "" when it never finished
	elapsed   float64
	output    []string
	children  []*node
}

// Line is one row of the summary: a scenario id, an OS and a tenant.
type Line struct {
	ID, OS, Tenant string
	Status         string // PASS, FAIL, CHAN, SKIP
	Tests          []string
	Detail         string
	Elapsed        float64
	// Output is what the failed tests of the line printed (framing
	// removed): the steps, job ids and step changes behind Detail.
	Output []string
}

// Report is the outcome of a run.
type Report struct {
	Tier          string
	Lines         []Line
	Missing       []string // catalogue ids that neither ran nor were skipped
	Unreasoned    []string // skips with no written reason
	PackageErrors []string // packages that failed outside any test
	Unfinished    []string // tests that started and never ended
	TopLevelRun   int      // top-level tests of the selection's prefixes
	NoTests       bool
}

// StatusChan is a line whose tests failed only because the test channel to
// their VM (its Bastion tunnel, SSH or WinRM) was unavailable: a gate
// problem, not a product result (W10). It fails the run like FAIL, and is
// counted and reported apart from it.
const StatusChan = "CHAN"

// channelTag is what harness.ChannelError's message starts with
// (harness.ChannelUnavailableTag; uatreport does not import the harness).
const channelTag = "UAT CHANNEL UNAVAILABLE"

// failLines are the "FAIL:" messages of harness.Scenario a test printed.
func failLines(n *node) []string {
	var out []string
	for _, l := range meaningful(n) {
		if strings.Contains(l, " FAIL: ") {
			out = append(out, l)
		}
	}
	return out
}

// channelOnly reports whether a failed test failed only on the channel:
// every failure it printed is a ChannelError (a product failure after a
// channel one still makes it a product failure).
func channelOnly(n *node) bool {
	fails := failLines(n)
	if len(fails) == 0 {
		return strings.Contains(failureDetail(n), channelTag)
	}
	for _, l := range fails {
		if !strings.Contains(l, channelTag) {
			return false
		}
	}
	return true
}

// productDetail is the first failure that is not the channel's, else
// failureDetail.
func productDetail(n *node) string {
	for _, l := range failLines(n) {
		if !strings.Contains(l, channelTag) {
			return l
		}
	}
	return failureDetail(n)
}

// Failed reports whether the run must exit non-zero.
func (r *Report) Failed() bool {
	if r.NoTests || len(r.Missing) > 0 || len(r.Unreasoned) > 0 || len(r.PackageErrors) > 0 || len(r.Unfinished) > 0 {
		return true
	}
	for _, l := range r.Lines {
		if l.Status == "FAIL" || l.Status == StatusChan {
			return true
		}
	}
	return false
}

var (
	topLevel  = regexp.MustCompile(`^Test(Smoke|Core|Resilience|Ingredients|Lifecycle|HA)([A-Z]{1,2}[0-9]+)?(?:_|$|[A-Z])`)
	osRe      = regexp.MustCompile(`(?:^|[^a-z])(ubuntu|alma|windows|win)(?:$|[^a-z])`)
	tenantRe  = regexp.MustCompile(`(?:^|[^a-z0-9])t([0-9]+)(?:$|[^0-9])`)
	ingredRe  = regexp.MustCompile(`I\.[a-z0-9_]+(?:\.[a-z0-9_]+)+`)
	framingRe = regexp.MustCompile(`^\s*(=== (RUN|PAUSE|CONT|NAME)|--- (PASS|FAIL|SKIP)|PASS$|FAIL$|ok\s|FAIL\s)`)
	sourceRe  = regexp.MustCompile(`^\s*[\w.-]+\.go:\d+: ?`)
)

// ReadEvents parses go test -json output. Lines that aren't JSON (a build
// failure printed by go itself) are kept as package output.
func ReadEvents(r io.Reader) ([]Event, error) {
	var out []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil || e.Action == "" {
			out = append(out, Event{Action: "output", Package: "(not json)", Output: line + "\n"})
			continue
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// Summarize builds the report of a run from its events.
func Summarize(cat *Catalogue, sel *Selection, events []Event) *Report {
	rep := &Report{Tier: sel.Tier}
	nodes := map[string]*node{}
	var order []*node
	get := func(pkg, name string) *node {
		k := pkg + "\x00" + name
		n, ok := nodes[k]
		if !ok {
			n = &node{pkg: pkg, name: name}
			nodes[k] = n
			order = append(order, n)
		}
		return n
	}
	pkgFailed := map[string]bool{}
	for _, e := range events {
		n := get(e.Package, e.Test)
		switch e.Action {
		case "output":
			n.output = append(n.output, strings.TrimRight(e.Output, "\n"))
		case "pass", "fail", "skip":
			n.status = e.Action
			n.elapsed = e.Elapsed
			if e.Test == "" && e.Action == "fail" {
				pkgFailed[e.Package] = true
			}
		}
	}
	// Link children to parents.
	for _, n := range order {
		if n.name == "" {
			continue
		}
		if i := strings.LastIndex(n.name, "/"); i >= 0 {
			if p, ok := nodes[n.pkg+"\x00"+n.name[:i]]; ok {
				p.children = append(p.children, n)
			}
		}
	}

	prefixes := map[string]bool{}
	for _, p := range cat.Prefixes(sel) {
		prefixes[p] = true
	}
	lines := map[string]*Line{}
	var lineOrder []string
	present := map[string]bool{} // id -> some test for it ran or was skipped
	failedTests := map[string]bool{}

	for _, n := range order {
		if n.name == "" || strings.Contains(n.name, "/") {
			continue
		}
		m := topLevel.FindStringSubmatch(n.name)
		if m == nil || !prefixes[m[1]] {
			continue
		}
		rep.TopLevelRun++
		for _, c := range contributors(n) {
			id := lineID(n, c, m)
			present[id] = true
			osName, tenant := placeOf(c.name)
			key := id + "\x00" + osName + "\x00" + tenant
			l, ok := lines[key]
			if !ok {
				l = &Line{ID: id, OS: osName, Tenant: tenant}
				lines[key] = l
				lineOrder = append(lineOrder, key)
			}
			l.Tests = append(l.Tests, c.name)
			l.Elapsed += elapsedOf(c)
			switch c.status {
			case "fail":
				failedTests[c.pkg] = true
				l.Output = append(l.Output, outputOf(c)...)
				// A product failure outranks a channel one on the
				// same line; either outranks a pass or a skip.
				switch {
				case channelOnly(c):
					if l.Status != "FAIL" && l.Status != StatusChan {
						l.Status, l.Detail = StatusChan, failureDetail(c)
					}
				case l.Status != "FAIL":
					l.Status = "FAIL"
					l.Detail = productDetail(c)
				}
			case "pass":
				if l.Status == "" || l.Status == "SKIP" {
					l.Status, l.Detail = "PASS", ""
				}
			case "skip":
				reason := skipReason(c)
				if reason == "" {
					rep.Unreasoned = append(rep.Unreasoned, c.name)
				}
				if l.Status == "" {
					l.Status, l.Detail = "SKIP", reason
				}
			default:
				rep.Unfinished = append(rep.Unfinished, c.pkg+" "+c.name)
				l.Output = append(l.Output, outputOf(c)...)
				if l.Status != "FAIL" {
					l.Status, l.Detail = "FAIL", "never finished (timeout or panic): "+lastOutput(c, 3)
				}
			}
		}
	}
	for _, k := range lineOrder {
		l := lines[k]
		rep.Lines = append(rep.Lines, *l)
	}
	sort.SliceStable(rep.Lines, func(i, j int) bool { return lineLess(cat, rep.Lines[i], rep.Lines[j]) })

	for pkg := range pkgFailed {
		if !failedTests[pkg] {
			rep.PackageErrors = append(rep.PackageErrors, pkg+": "+lastOutput(nodes[pkg+"\x00"], 8))
		}
	}
	if n, ok := nodes["(not json)\x00"]; ok {
		rep.PackageErrors = append(rep.PackageErrors, "go test printed: "+lastOutput(n, 8))
	}
	sort.Strings(rep.PackageErrors)

	rep.NoTests = rep.TopLevelRun == 0
	for _, s := range cat.Expected(sel) {
		// A skip without a reason is reported as Unreasoned, so being
		// present is enough here.
		if !present[s.ID] {
			rep.Missing = append(rep.Missing, s.ID+" ("+s.Title+"; "+s.Owner+")")
		}
	}
	if cat.ExpectsIngredients(sel) {
		if len(sel.Ingredient) == 0 {
			found := false
			for id := range present {
				if IngredientID.MatchString(id) || strings.HasPrefix(id, "Ingredients") {
					found = true
				}
			}
			if !found {
				rep.Missing = append(rep.Missing, "I.* (no ingredient conformance test ran; UAT.7)")
			}
		}
		for _, id := range sel.Ingredient {
			if !present[id] {
				rep.Missing = append(rep.Missing, id+" (ingredient case)")
			}
		}
	}
	return rep
}

// contributors are the nodes a top-level test reports through: its
// leaves, plus any test that failed on its own (no failed child).
func contributors(n *node) []*node {
	if len(n.children) == 0 {
		return []*node{n}
	}
	var out []*node
	childFailed := false
	for _, c := range n.children {
		out = append(out, contributors(c)...)
		if c.status == "fail" {
			childFailed = true
		}
	}
	if (n.status == "fail" && !childFailed) || n.status == "" {
		out = append(out, n)
	}
	return out
}

// lineID is the scenario id a test reports under: the top-level test's
// id, an I.name.method in an ingredient test's path, or the top-level
// name without "Test".
func lineID(top, c *node, m []string) string {
	if m[2] != "" {
		return m[2]
	}
	if id := ingredRe.FindString(c.name); id != "" {
		return id
	}
	return strings.TrimPrefix(top.name, "Test")
}

// placeOf reads the OS and tenant from a test's subtest names (t1,
// t1-ubuntu, ubuntu_t2, t2-win, ...). "-" when the path names none.
func placeOf(name string) (osName, tenant string) {
	osName, tenant = "-", "-"
	parts := strings.Split(name, "/")
	for _, p := range parts[1:] {
		lp := strings.ToLower(p)
		if m := osRe.FindStringSubmatch(lp); m != nil {
			osName = m[1]
			if osName == "win" {
				osName = "windows"
			}
		}
		if m := tenantRe.FindStringSubmatch(lp); m != nil {
			tenant = m[1]
		}
	}
	return osName, tenant
}

// caseTimeRe is the line ingredients.Replay logs with a case's own run
// time on its sprout.
var caseTimeRe = regexp.MustCompile(`case time on this sprout: (\S+)`)

// elapsedOf is a test's time: go test's, or the case time it logged when
// that is longer. A parallel subtest that only collects an outcome
// computed earlier (TestIngredients, on any OS) reports about 0 s to go
// test although its case ran for minutes.
func elapsedOf(n *node) float64 {
	el := n.elapsed
	for _, l := range n.output {
		if m := caseTimeRe.FindStringSubmatch(l); m != nil {
			if d, err := time.ParseDuration(m[1]); err == nil && d.Seconds() > el {
				el = d.Seconds()
			}
		}
	}
	return el
}

// maxOutputLines and maxLineBytes bound the output one failed test adds
// to the JUnit file: at most 200 lines of at most 2000 bytes each.
const (
	maxOutputLines = 200
	maxLineBytes   = 2000
)

// outputOf is what a failed test printed, for the JUnit failure body: its
// first lines and its last, when it printed more than maxOutputLines, each
// cut at maxLineBytes.
func outputOf(n *node) []string {
	lines := meaningful(n)
	for i, l := range lines {
		if len(l) > maxLineBytes {
			lines[i] = strings.ToValidUTF8(l[:maxLineBytes], "") + fmt.Sprintf("... (%d bytes left out)", len(l)-maxLineBytes)
		}
	}
	if len(lines) > maxOutputLines {
		head := lines[:maxOutputLines/4]
		tail := lines[len(lines)-3*maxOutputLines/4:]
		lines = append(append(append([]string{}, head...), fmt.Sprintf("... (%d lines left out; events.json and build.log have them all)", len(lines)-maxOutputLines)), tail...)
	}
	if len(lines) == 0 {
		return nil
	}
	return append([]string{"--- " + n.name + ":"}, lines...)
}

func meaningful(n *node) []string {
	var out []string
	for _, l := range n.output {
		if strings.TrimSpace(l) == "" || framingRe.MatchString(l) {
			continue
		}
		out = append(out, strings.TrimSpace(sourceRe.ReplaceAllString(l, "")))
	}
	return out
}

// skipReason is the text after "SKIP: " (harness.Scenario.Skipf), or the
// last line the skipped test printed; "" when it printed nothing.
func skipReason(n *node) string {
	lines := meaningful(n)
	for _, l := range lines {
		if i := strings.Index(l, " SKIP: "); i >= 0 {
			return strings.TrimSpace(l[i+len(" SKIP: "):])
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}

// failureDetail is the first "FAIL:" message of harness.Scenario, or the
// last lines the test printed.
func failureDetail(n *node) string {
	for _, l := range meaningful(n) {
		if strings.Contains(l, " FAIL: ") {
			return l
		}
	}
	return lastOutput(n, 3)
}

func lastOutput(n *node, k int) string {
	if n == nil {
		return "(no output)"
	}
	lines := meaningful(n)
	if len(lines) > k {
		lines = lines[len(lines)-k:]
	}
	if len(lines) == 0 {
		return "(no output)"
	}
	return strings.Join(lines, " | ")
}

func lineLess(cat *Catalogue, a, b Line) bool {
	ia, ib := catIndex(cat, a.ID), catIndex(cat, b.ID)
	if ia != ib {
		return ia < ib
	}
	if a.ID != b.ID {
		return a.ID < b.ID
	}
	if a.Tenant != b.Tenant {
		return a.Tenant < b.Tenant
	}
	return a.OS < b.OS
}

func catIndex(cat *Catalogue, id string) int {
	for i, s := range cat.Scenarios {
		if s.ID == id {
			return i
		}
	}
	for i, s := range cat.Scenarios {
		if s.ID == ingredientWildcard {
			return i
		}
	}
	return len(cat.Scenarios)
}

// Print writes the human summary.
func (r *Report) Print(w io.Writer) {
	fmt.Fprintf(w, "UAT summary, tier %s\n", r.Tier)
	fmt.Fprintf(w, "%-6s %-22s %-8s %-6s %8s  %s\n", "STATUS", "ID", "OS", "TENANT", "SECONDS", "DETAIL")
	var pass, fail, chans, skip int
	for _, l := range r.Lines {
		switch l.Status {
		case "PASS":
			pass++
		case "FAIL":
			fail++
		case StatusChan:
			chans++
		case "SKIP":
			skip++
		}
		fmt.Fprintf(w, "%-6s %-22s %-8s %-6s %8.1f  %s\n", l.Status, l.ID, l.OS, l.Tenant, l.Elapsed, oneLine(l.Detail, 300))
	}
	for _, m := range r.Missing {
		fmt.Fprintf(w, "%-6s %-22s %-8s %-6s %8s  %s\n", "MISS", strings.SplitN(m, " ", 2)[0], "-", "-", "-", "neither ran nor was skipped with a reason: "+m)
	}
	fmt.Fprintf(w, "\nSkipped (%d), with their reasons:\n", skip)
	for _, l := range r.Lines {
		if l.Status == "SKIP" {
			fmt.Fprintf(w, "  %s os=%s tenant=%s: %s\n", l.ID, l.OS, l.Tenant, oneLine(l.Detail, 400))
		}
	}
	for _, u := range r.Unreasoned {
		fmt.Fprintf(w, "  SKIPPED WITHOUT A REASON: %s\n", u)
	}
	for _, p := range r.PackageErrors {
		fmt.Fprintf(w, "PACKAGE FAILURE: %s\n", oneLine(p, 600))
	}
	for _, u := range r.Unfinished {
		fmt.Fprintf(w, "NEVER FINISHED: %s\n", u)
	}
	if r.NoTests {
		fmt.Fprintf(w, "NO TEST MATCHED tier %s: a run that runs nothing is a failure\n", r.Tier)
	}
	if chans > 0 {
		fmt.Fprintf(w, "\nCHAN (%d): channel unavailable: the test channel to the VM (its Bastion tunnel, SSH or WinRM) was down, "+
			"so these did not test the product; read report/diagnostics/channel/ and diagnostics/<vm>/ (uat/RUNBOOK.md, \"The test channel\")\n", chans)
	}
	fmt.Fprintf(w, "\nlines: %d pass, %d fail, %d channel unavailable, %d skip; missing scenarios: %d; top-level tests run: %d\n",
		pass, fail, chans, skip, len(r.Missing), r.TopLevelRun)
	if r.Failed() {
		fmt.Fprintln(w, "RESULT: FAIL")
	} else {
		fmt.Fprintln(w, "RESULT: PASS")
	}
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		s = s[:max] + "..."
	}
	return s
}

type junitSuites struct {
	XMLName xml.Name     `xml:"testsuites"`
	Suites  []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Errors   int         `xml:"errors,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []junitCase `xml:"testcase"`
}

// junitCase: a product failure is a <failure>, a channel unavailable line
// an <error type="channel-unavailable"> (JUnit's "could not run"), so a
// JUnit reader tells them apart too.
type junitCase struct {
	Class   string        `xml:"classname,attr"`
	Name    string        `xml:"name,attr"`
	Time    string        `xml:"time,attr"`
	Failure *junitMessage `xml:"failure,omitempty"`
	Error   *junitMessage `xml:"error,omitempty"`
	Skipped *junitMessage `xml:"skipped,omitempty"`
}

type junitMessage struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr,omitempty"`
	Body    string `xml:",chardata"`
}

// WriteJUnit writes the report as JUnit XML: one test case per line, and
// one failing case per missing scenario or package failure.
func (r *Report) WriteJUnit(w io.Writer) error {
	s := junitSuite{Name: "imas-uat-" + r.Tier}
	for _, l := range r.Lines {
		c := junitCase{Class: "uat." + l.ID, Name: fmt.Sprintf("%s os=%s tenant=%s", l.ID, l.OS, l.Tenant), Time: fmt.Sprintf("%.1f", l.Elapsed)}
		switch l.Status {
		case "FAIL", StatusChan:
			body := l.Detail + "\ntests: " + strings.Join(l.Tests, ", ")
			if len(l.Output) > 0 {
				body += "\n\noutput:\n" + strings.Join(l.Output, "\n")
			}
			if l.Status == StatusChan {
				c.Error = &junitMessage{Message: oneLine("channel unavailable: "+l.Detail, 300), Type: "channel-unavailable", Body: body}
				s.Errors++
				break
			}
			c.Failure = &junitMessage{Message: oneLine(l.Detail, 300), Body: body}
			s.Failures++
		case "SKIP":
			c.Skipped = &junitMessage{Message: oneLine(l.Detail, 300)}
			s.Skipped++
		}
		s.Cases = append(s.Cases, c)
	}
	add := func(class, name, msg string) {
		s.Cases = append(s.Cases, junitCase{Class: class, Name: name, Time: "0", Failure: &junitMessage{Message: oneLine(msg, 300), Body: msg}})
		s.Failures++
	}
	for _, m := range r.Missing {
		add("uat.missing", strings.SplitN(m, " ", 2)[0], "neither ran nor was skipped with a reason: "+m)
	}
	for _, u := range r.Unreasoned {
		add("uat.unreasoned-skip", u, "skipped without a written reason")
	}
	for _, p := range r.PackageErrors {
		add("uat.package", "package failure", p)
	}
	for _, u := range r.Unfinished {
		add("uat.unfinished", u, "never finished")
	}
	if r.NoTests {
		add("uat.tier", "no tests", "no test matched tier "+r.Tier)
	}
	s.Tests = len(s.Cases)
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	if err := enc.Encode(junitSuites{Suites: []junitSuite{s}}); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}
