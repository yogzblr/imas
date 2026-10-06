package ingredients

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Skip is a documented reason a case doesn't run on an OS.
type Skip struct {
	ID     string
	OS     string // a sprout OS, or "all"
	Reason string
}

// CoverageReport is the outcome of checking the cases against the
// registry.
type CoverageReport struct {
	// Methods is the number of registered methods; Pairs the number of
	// (method, OS) pairs over the sprout OSes; Runnable how many pairs a
	// case runs on; Skipped how many have a written skip instead.
	Methods, Pairs, Runnable, Skipped int
	// Cases is the number of case files.
	Cases int
	// Missing lists (method, OS) pairs with neither a case nor a skip.
	Missing []string
	// Problems lists cases that don't fit the registry.
	Problems []string
	// Skips lists every documented skip, by id and OS.
	Skips []Skip
}

// Err is non-nil when the coverage rule is broken: a registered method on
// an OS has neither a case nor a written skip, or a case doesn't fit the
// registry.
func (r *CoverageReport) Err() error {
	var errs []error
	for _, m := range r.Missing {
		errs = append(errs, errors.New("missing: "+m))
	}
	for _, p := range r.Problems {
		errs = append(errs, errors.New("case: "+p))
	}
	return errors.Join(errs...)
}

// Coverage checks the cases against the registry: every registered method
// on every sprout OS it applies to must have a case that runs there or a
// written skip; every case must name a registered method (or an
// unreachable one, or a backend, with a skip or a recipe that exercises
// it), list only OSes the method is registered on, and cook the method it
// is named after.
func Coverage(reg *Registry, cases []*Case) *CoverageReport {
	rep := &CoverageReport{Methods: len(reg.Methods), Cases: len(cases)}
	byID := map[string]*Case{}
	for _, c := range cases {
		byID[c.ID] = c
	}
	unreachable := map[string]Method{}
	for _, m := range reg.Unreachable {
		unreachable[m.ID()] = m
	}
	backends := map[string]bool{}
	for _, b := range reg.Backends {
		backends[strings.ReplaceAll(b.Registry, " ", "-")+":"+b.Name] = true
	}

	for _, m := range reg.Methods {
		c, ok := byID[m.ID()]
		for _, os := range m.OSes() {
			rep.Pairs++
			if !ok {
				rep.Missing = append(rep.Missing, fmt.Sprintf("%s on %s: no case file %s/%s.yaml", m.ID(), os, m.Ingredient, m.Method))
				continue
			}
			runs, reason := c.Runs(os)
			switch {
			case runs:
				rep.Runnable++
			case reason != "":
				rep.Skipped++
			default:
				rep.Missing = append(rep.Missing, fmt.Sprintf("%s on %s: the case neither lists %s in os nor gives a skip_os reason", m.ID(), os, os))
			}
		}
	}

	for _, c := range cases {
		m, registered := reg.Get(c.ID)
		um, isUnreachable := unreachable[c.ID]
		var oses []string
		switch {
		case registered:
			oses = m.OSes()
		case isUnreachable:
			oses = um.OSes()
			if c.Skip == "" {
				rep.Problems = append(rep.Problems, fmt.Sprintf("%s: %s registers it but no sprout imports that package, so the case can only be a skip", c.ID, um.Package))
			}
		case c.Backend != "":
			if !backends[c.Backend] {
				rep.Problems = append(rep.Problems, fmt.Sprintf("%s: backend %s is not registered", c.ID, c.Backend))
			}
			oses = KnownOSes
		default:
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s (%s): no such registered method", c.ID, c.File))
			continue
		}
		allowed := map[string]bool{}
		for _, o := range oses {
			allowed[o] = true
		}
		for _, o := range c.OS {
			if !allowed[o] {
				rep.Problems = append(rep.Problems, fmt.Sprintf("%s: lists %s, but the method is registered only for %s", c.ID, o, strings.Join(oses, ", ")))
			}
		}
		for o := range c.SkipOS {
			if !allowed[o] {
				rep.Problems = append(rep.Problems, fmt.Sprintf("%s: skip_os names %s, where the method isn't registered", c.ID, o))
			}
		}
		if c.Skip != "" {
			rep.Skips = append(rep.Skips, Skip{ID: c.ID, OS: "all", Reason: c.Skip})
			continue
		}
		for o, r := range c.SkipOS {
			rep.Skips = append(rep.Skips, Skip{ID: c.ID, OS: o, Reason: r})
		}
		if c.Backend != "" {
			continue
		}
		want := c.Ingredient() + "." + c.Method()
		for _, o := range c.OS {
			used, err := StepMethods(c.For(o).Recipe)
			if err != nil {
				rep.Problems = append(rep.Problems, fmt.Sprintf("%s on %s: %v", c.ID, o, err))
				continue
			}
			found := false
			for _, u := range used {
				if u == want {
					found = true
				}
			}
			if !found {
				rep.Problems = append(rep.Problems, fmt.Sprintf("%s on %s: the recipe doesn't use %s (it uses %s)", c.ID, o, want, strings.Join(used, ", ")))
			}
		}
	}
	sort.Strings(rep.Missing)
	sort.Strings(rep.Problems)
	sort.Slice(rep.Skips, func(i, j int) bool {
		if rep.Skips[i].ID != rep.Skips[j].ID {
			return rep.Skips[i].ID < rep.Skips[j].ID
		}
		return rep.Skips[i].OS < rep.Skips[j].OS
	})
	return rep
}

// String is the report as text: the counts, the gaps and every skip with
// its reason.
func (r *CoverageReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "ingredient coverage: %d registered methods, %d (method, OS) pairs: %d run, %d skipped with a reason, %d missing; %d case files\n",
		r.Methods, r.Pairs, r.Runnable, r.Skipped, len(r.Missing), r.Cases)
	for _, m := range r.Missing {
		fmt.Fprintf(&b, "MISSING %s\n", m)
	}
	for _, p := range r.Problems {
		fmt.Fprintf(&b, "PROBLEM %s\n", p)
	}
	for _, s := range r.Skips {
		fmt.Fprintf(&b, "SKIP    %-40s %-8s %s\n", s.ID, s.OS, oneLine(s.Reason))
	}
	return b.String()
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
