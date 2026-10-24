package pkg

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gogrlx/snack"
	"github.com/yogzblr/imas/internal/cook"
)

// A url of "ppa:<owner>/<name>" (or "ppa:<owner>", Launchpad's default
// archive "ppa") is a Launchpad PPA. Only add-apt-repository knows how to
// turn that into a source and fetch its signing key, so a PPA goes through
// snack's AddRepo/RemoveRepo, which run it. Whether it is configured is
// read from the source files here, though: snack's apt ListRepos lists
// one-line entries under their full line (never under the recipe's name)
// and doesn't read the deb822 .sources files add-apt-repository writes on
// Ubuntu 24.04.

// aptSourcesList is the main one-line sources file. For tests.
var aptSourcesList = "/etc/apt/sources.list"

// lookPath finds a command on PATH. For tests.
var lookPath = exec.LookPath

var ppaShortcut = regexp.MustCompile(`^ppa:([a-z0-9][a-z0-9.+-]*)(?:/([a-z0-9][a-z0-9.+-]*))?$`)

func isPPAShortcut(url string) bool {
	return strings.HasPrefix(strings.TrimSpace(url), "ppa:")
}

// ppaArchive returns the owner and archive name of a ppa: shortcut.
func ppaArchive(shortcut string) (owner, name string, err error) {
	m := ppaShortcut.FindStringSubmatch(shortcut)
	if m == nil {
		return "", "", fmt.Errorf("%q is not a PPA shortcut: want ppa:<owner>/<name> in lowercase letters, digits, '.', '+' and '-'", shortcut)
	}
	name = m[2]
	if name == "" {
		name = "ppa"
	}
	return m[1], name, nil
}

// ppaHosts are the hosts Launchpad serves PPAs from, new and old.
var ppaHosts = map[string]bool{"ppa.launchpadcontent.net": true, "ppa.launchpad.net": true}

// ppaConfigured reports the source files with an active entry for the PPA:
// a URI on a Launchpad PPA host whose path is /<owner>/<name>/ubuntu.
func ppaConfigured(owner, name string) ([]string, error) {
	files := []string{aptSourcesList}
	for _, glob := range []string{"*" + aptListExt, "*" + aptSourcesExt} {
		m, err := filepath.Glob(filepath.Join(aptSourcesDir, glob))
		if err != nil {
			return nil, err
		}
		files = append(files, m...)
	}
	var found []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, u := range sourceURIs(b) {
			if isPPAURI(u, owner, name) {
				found = append(found, f)
				break
			}
		}
	}
	return found, nil
}

// isPPAURI reports whether u is the archive of PPA owner/name.
func isPPAURI(u, owner, name string) bool {
	parsed, err := url.Parse(u)
	if err != nil || !ppaHosts[strings.ToLower(parsed.Hostname())] {
		return false
	}
	return strings.Trim(parsed.Path, "/") == owner+"/"+name+"/ubuntu"
}

// sourceURIs returns the repository URIs of a sources file's active
// entries: the URI of each uncommented one-line entry (after its type and
// [options]) and every value of a deb822 URIs field, continuation lines
// included.
func sourceURIs(b []byte) []string {
	var uris []string
	inURIs := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		raw := sc.Text()
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "#") {
			inURIs = false
			continue
		}
		if inURIs && (raw[0] == ' ' || raw[0] == '\t') {
			uris = append(uris, strings.Fields(l)...)
			continue
		}
		inURIs = false
		if f, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(f), "URIs") {
			uris = append(uris, strings.Fields(v)...)
			inURIs = true
			continue
		}
		fields := strings.Fields(l)
		if fields[0] != "deb" && fields[0] != "deb-src" {
			continue
		}
		rest := fields[1:]
		if len(rest) > 0 && strings.HasPrefix(rest[0], "[") {
			for len(rest) > 0 && !strings.Contains(rest[0], "]") {
				rest = rest[1:]
			}
			if len(rest) > 0 {
				rest = rest[1:]
			}
		}
		if len(rest) > 0 {
			uris = append(uris, rest[0])
		}
	}
	return uris
}

func (p Pkg) ppaManaged(ctx context.Context, mgr snack.Manager, shortcut string, test bool) (cook.Result, error) {
	owner, name, err := ppaArchive(shortcut)
	if err != nil {
		return failResult(fmt.Errorf("apt repository %s: %w", p.name, err))
	}
	repoMgr, ok := mgr.(snack.RepoManager)
	if !ok {
		return failResult(errRepoNotSupported)
	}
	found, err := ppaConfigured(owner, name)
	if err != nil {
		return failResult(err)
	}
	absent := getBoolProp(p.properties, "absent", false)
	switch {
	case absent && len(found) == 0:
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{note("repository already absent: %s (%s)", p.name, shortcut)}}, nil
	case !absent && len(found) > 0:
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{note("repository already configured: %s (%s in %s)", p.name, shortcut, strings.Join(found, ", "))}}, nil
	}
	verb := "add"
	if absent {
		verb = "remove"
	}
	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{note("would %s repository %s (%s, add-apt-repository)", verb, p.name, shortcut)}}, nil
	}
	if _, err := lookPath("add-apt-repository"); err != nil {
		return failResult(fmt.Errorf("apt repository %s: a ppa: url needs add-apt-repository (package software-properties-common): %w", p.name, err))
	}
	if absent {
		err = repoMgr.RemoveRepo(ctx, shortcut)
	} else {
		err = repoMgr.AddRepo(ctx, snack.Repository{ID: p.name, Name: p.name, URL: shortcut})
	}
	if err != nil {
		return failResult(err)
	}
	// add-apt-repository reports success when it did nothing (an unknown
	// archive on --remove, say): check the result like the next cook will.
	after, err := ppaConfigured(owner, name)
	if err != nil {
		return failResult(err)
	}
	if absent && len(after) > 0 {
		return cook.Result{Succeeded: false, Failed: true, Changed: true}, fmt.Errorf("apt repository %s: add-apt-repository --remove %s left it in %s", p.name, shortcut, strings.Join(after, ", "))
	}
	if !absent && len(after) == 0 {
		return cook.Result{Succeeded: false, Failed: true, Changed: true}, fmt.Errorf("apt repository %s: add-apt-repository %s wrote no source for ppa.launchpadcontent.net/%s/%s", p.name, shortcut, owner, name)
	}
	done := "added"
	if absent {
		done = "removed"
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{note("%s repository %s (%s)", done, p.name, shortcut)}}, nil
}
