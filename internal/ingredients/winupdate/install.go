//go:build windows

package winupdate

import (
	"context"
	"fmt"
	"strings"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

// defaultSearchCriteria matches Salt's win_wua default: not-yet-
// installed, non-hidden software updates.
const defaultSearchCriteria = "IsInstalled=0 and Type='Software' and IsHidden=0"

// updateInfo is a plain-data snapshot of a WUA IUpdate object -- no
// live COM pointer is ever carried in one of these, so they're safe to
// return across a backend call boundary (and to fake in tests).
type updateInfo struct {
	Title        string
	KBArticleIDs []string
	IsInstalled  bool
	EulaAccepted bool
}

// installOutcome reports what an Install call actually did.
type installOutcome struct {
	Installed      []string // titles of updates installed
	Skipped        []string // titles skipped because their EULA wasn't accepted
	RebootRequired bool
}

// updateBackend abstracts the COM-backed WUA calls this ingredient
// needs, so tests can substitute an in-memory fake instead of touching
// a real Windows Update Agent and COM apartment.
type updateBackend interface {
	// Search returns every update WUA reports matching criteria.
	Search(criteria string) ([]updateInfo, error)
	// Install runs its own search+download+install pass restricted to
	// not-yet-installed updates whose KB article IDs are in wantedKBs
	// (normalized -- see normalizeKB), using criteria as the base search
	// filter. It never installs anything outside wantedKBs.
	Install(criteria string, wantedKBs map[string]bool, acceptEula bool) (installOutcome, error)
}

// backend is replaceable in tests.
var backend updateBackend = oleUpdateBackend{}

func normalizeKB(id string) string {
	id = strings.ToUpper(strings.TrimSpace(id))
	return strings.TrimPrefix(id, "KB")
}

func buildWantedSet(kbIDs []string) map[string]bool {
	wanted := make(map[string]bool, len(kbIDs))
	for _, id := range kbIDs {
		wanted[normalizeKB(id)] = true
	}
	return wanted
}

func matchesAnyKB(u updateInfo, wanted map[string]bool) bool {
	for _, kb := range u.KBArticleIDs {
		if wanted[normalizeKB(kb)] {
			return true
		}
	}
	return false
}

func (u Update) installed(_ context.Context, test bool) (cook.Result, error) {
	kbIDs, _ := winexec.StringSliceParam(u.params, "kb_ids")
	criteria := winexec.StringParamOr(u.params, "search_criteria", defaultSearchCriteria)
	acceptEula := winexec.BoolParam(u.params, "accept_eula", true)
	wanted := buildWantedSet(kbIDs)

	found, err := backend.Search(criteria)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}

	missing := 0
	for _, upd := range found {
		if !upd.IsInstalled && matchesAnyKB(upd, wanted) {
			missing++
		}
	}

	if missing == 0 {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("all %d requested update(s) are already installed", len(kbIDs)),
		}}, nil
	}

	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("%d update(s) would be installed", missing),
		}}, nil
	}

	outcome, err := backend.Install(criteria, wanted, acceptEula)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}

	notes := []fmt.Stringer{
		cook.Snprintf("installed %d update(s): %s", len(outcome.Installed), strings.Join(outcome.Installed, ", ")),
	}
	if outcome.RebootRequired {
		notes = append(notes, cook.Snprintf("a reboot is required to complete installation"))
	}
	if len(outcome.Skipped) > 0 {
		notes = append(notes, cook.Snprintf("skipped %d update(s) pending EULA acceptance: %s", len(outcome.Skipped), strings.Join(outcome.Skipped, ", ")))
	}

	return cook.Result{Succeeded: true, Changed: len(outcome.Installed) > 0, Notes: notes}, nil
}
