// Command uatreport is the bookkeeping half of uat/tests/run.sh: it turns
// a tier and scenario ids into a go test -run pattern, and turns the
// test2json events of a run into the summary, a JUnit file and an exit
// status that enforces the no silent green rule of plan section 4h:
// a run fails when no test matched the tier, when a catalogue scenario of
// the tier neither ran nor was skipped with a written reason, when a skip
// has no reason, or when a package failed outside any test.
//
//	uatreport pattern   -catalogue FILE -tier TIER [id ...]
//	uatreport summarize -catalogue FILE -tier TIER [-junit FILE] [id ...] < events.json
//	uatreport follow < events.json     (prints the tests' output as it comes)
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: uatreport pattern|summarize -catalogue FILE -tier TIER [-junit FILE] [id ...]")
		return 2
	}
	cmd := args[0]
	if cmd == "follow" {
		return follow(stdin, stdout)
	}
	fs := flag.NewFlagSet("uatreport "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	catalogue := fs.String("catalogue", "", "catalogue.tsv")
	tier := fs.String("tier", "", "smoke, core, resilience, ingredients, lifecycle or all")
	junit := fs.String("junit", "", "write a JUnit XML report here (summarize)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *catalogue == "" || *tier == "" {
		fmt.Fprintln(stderr, "uatreport: -catalogue and -tier are required")
		return 2
	}
	cat, err := LoadCatalogue(*catalogue)
	if err != nil {
		fmt.Fprintf(stderr, "uatreport: %v\n", err)
		return 2
	}
	sel, err := cat.Select(*tier, fs.Args())
	if err != nil {
		fmt.Fprintf(stderr, "uatreport: %v\n", err)
		return 2
	}
	switch cmd {
	case "pattern":
		fmt.Fprintln(stdout, cat.RunPattern(sel))
		return 0
	case "summarize":
		events, err := ReadEvents(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "uatreport: reading events: %v\n", err)
			return 2
		}
		rep := Summarize(cat, sel, events)
		rep.Print(stdout)
		if *junit != "" {
			f, err := os.Create(*junit)
			if err != nil {
				fmt.Fprintf(stderr, "uatreport: %v\n", err)
				return 2
			}
			werr := rep.WriteJUnit(f)
			if cerr := f.Close(); werr == nil {
				werr = cerr
			}
			if werr != nil {
				fmt.Fprintf(stderr, "uatreport: writing %s: %v\n", *junit, werr)
				return 2
			}
		}
		if rep.Failed() {
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "uatreport: unknown command %q\n", cmd)
		return 2
	}
}

// follow prints the Output of each test2json event, so a run shows its
// progress while run.sh keeps the events for the summary. A line that
// isn't an event is printed as it is.
func follow(stdin io.Reader, stdout io.Writer) int {
	sc := bufio.NewScanner(stdin)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil || e.Action == "" {
			fmt.Fprintln(stdout, sc.Text())
			continue
		}
		if e.Action == "output" {
			fmt.Fprint(stdout, e.Output)
		}
	}
	return 0
}
