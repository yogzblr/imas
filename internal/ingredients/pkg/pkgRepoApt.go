package pkg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

// apt repositories are managed as source files written here, not through
// snack's AddRepo/RemoveRepo: those run add-apt-repository, which on
// Ubuntu 24.04 refuses ordinary one-line entries such as a flat
// repository ("deb [trusted=yes] file:/srv/repo ./": "Unable to handle
// repository shortcut") and isn't installed on Debian by default.

// Seams for tests. Production code always uses these values.
var (
	// aptSourcesDir is where the managed source files live.
	aptSourcesDir = "/etc/apt/sources.list.d"
	// aptUpdate refreshes apt's package lists after a source changed.
	aptUpdate = func(ctx context.Context) error {
		cmd := exec.CommandContext(ctx, "apt-get", "update")
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C")
		_, err := ingredients.RunCommand(cmd)
		return err
	}
)

const (
	aptListExt    = ".list"
	aptSourcesExt = ".sources"
)

// aptSourceName is what apt accepts as a sources.list.d file name (it
// silently ignores any other); the repository name becomes the file name.
var aptSourceName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

// deb822Field matches a deb822 field line ("Types: deb").
var deb822Field = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]*):`)

func checkAptSourceName(name string) error {
	if !aptSourceName.MatchString(name) {
		return fmt.Errorf("apt repository name %q: only letters, digits, '_', '-' and '.' are allowed (it names the file in %s)", name, aptSourcesDir)
	}
	return nil
}

// aptSource returns the file name (base, with extension) and content of the
// source file for repository name with entry url. url is either one-line
// style ("deb [opts] uri suite [components...]", one entry per line) or a
// deb822 stanza ("Types: deb\nURIs: ...").
func aptSource(name, url string) (string, []byte, error) {
	if err := checkAptSourceName(name); err != nil {
		return "", nil, err
	}
	entry := strings.TrimSpace(url)
	if entry == "" {
		return "", nil, errors.New("apt repository needs a url: a one-line entry (deb [options] uri suite [components]) or a deb822 stanza")
	}
	var lines []string
	for _, l := range strings.Split(entry, "\n") {
		lines = append(lines, strings.TrimRight(l, " \t\r"))
	}
	ext := aptListExt
	var err error
	if isDeb822(lines) {
		ext = aptSourcesExt
		err = checkDeb822(lines)
	} else {
		err = checkOneLine(lines)
	}
	if err != nil {
		return "", nil, fmt.Errorf("apt repository %s: %w", name, err)
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Managed by imas pkg.repo_managed (%s); local changes are overwritten.\n", name)
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return name + ext, b.Bytes(), nil
}

func isDeb822(lines []string) bool {
	for _, l := range lines {
		if m := deb822Field.FindStringSubmatch(l); m != nil && strings.EqualFold(m[1], "Types") {
			return true
		}
	}
	return false
}

// checkDeb822 requires each stanza to carry the fields apt needs.
func checkDeb822(lines []string) error {
	var stanzas []map[string]bool
	cur := map[string]bool{}
	for _, l := range append(lines, "") {
		switch {
		case strings.TrimSpace(l) == "":
			if len(cur) > 0 {
				stanzas = append(stanzas, cur)
				cur = map[string]bool{}
			}
		case strings.HasPrefix(l, "#"):
		case l[0] == ' ' || l[0] == '\t':
			if len(cur) == 0 {
				return fmt.Errorf("deb822 continuation line %q outside a field", l)
			}
		default:
			m := deb822Field.FindStringSubmatch(l)
			if m == nil {
				return fmt.Errorf("deb822 line %q is not a field", l)
			}
			cur[strings.ToLower(m[1])] = true
		}
	}
	for i, s := range stanzas {
		for _, f := range []string{"types", "uris", "suites"} {
			if !s[f] {
				return fmt.Errorf("deb822 stanza %d has no %s field", i+1, f)
			}
		}
	}
	return nil
}

// checkOneLine validates one-line entries: deb|deb-src, an optional
// [key=value ...] option list (trusted=yes, signed-by=, arch=, ...), the
// URI, then either an exact path ending in "/" (a flat repository, no
// components) or a suite and at least one component.
func checkOneLine(lines []string) error {
	n := 0
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if err := checkOneLineEntry(l); err != nil {
			return fmt.Errorf("%q: %w", l, err)
		}
		n++
	}
	if n == 0 {
		return errors.New("url has no entry")
	}
	return nil
}

func checkOneLineEntry(l string) error {
	fields := strings.Fields(l)
	if fields[0] != "deb" && fields[0] != "deb-src" {
		return errors.New("not an apt source entry: it must start with deb or deb-src (shortcuts such as ppa: are not supported)")
	}
	rest := fields[1:]
	if len(rest) > 0 && strings.HasPrefix(rest[0], "[") {
		end := -1
		for i, f := range rest {
			if strings.Contains(f, "]") {
				end = i
				break
			}
		}
		if end < 0 {
			return errors.New("option list has no closing ]")
		}
		opts := strings.Join(rest[:end+1], " ")
		if !strings.HasSuffix(opts, "]") || strings.Count(opts, "[") != 1 || strings.Count(opts, "]") != 1 {
			return errors.New("malformed option list")
		}
		for _, o := range strings.Fields(strings.Trim(opts, "[]")) {
			if k, _, ok := strings.Cut(o, "="); !ok || k == "" {
				return fmt.Errorf("option %q is not key=value", o)
			}
		}
		rest = rest[end+1:]
	}
	if len(rest) < 2 {
		return errors.New("needs a URI and a suite")
	}
	if !strings.Contains(rest[0], ":") {
		return fmt.Errorf("URI %q has no scheme", rest[0])
	}
	suite, components := rest[1], rest[2:]
	if strings.HasSuffix(suite, "/") {
		if len(components) > 0 {
			return errors.New("a flat repository (suite ending in /) takes no components")
		}
	} else if len(components) == 0 {
		return fmt.Errorf("suite %q needs at least one component (or end it in / for a flat repository)", suite)
	}
	return nil
}

// aptOtherExt is the extension of the other source-file form.
func aptOtherExt(ext string) string {
	if ext == aptListExt {
		return aptSourcesExt
	}
	return aptListExt
}

// fileState is a file's content before a change, for rolling it back.
type fileState struct {
	path    string
	content []byte
	existed bool
}

func readFileState(path string) (fileState, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileState{path: path}, nil
	}
	if err != nil {
		return fileState{}, err
	}
	return fileState{path: path, content: b, existed: true}, nil
}

func (s fileState) restore() error {
	if !s.existed {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return writeFileAtomic(s.path, s.content)
}

// writeFileAtomic replaces path with content (mode 0644) via a temporary
// file in the same directory, so apt never reads a half-written source.
func writeFileAtomic(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".imas-"+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (p Pkg) aptRepoManaged(ctx context.Context, test bool) (cook.Result, error) {
	if getBoolProp(p.properties, "absent", false) {
		return p.aptRepoRemoved(ctx, test)
	}
	return p.aptRepoAdded(ctx, test)
}

func (p Pkg) aptRepoAdded(ctx context.Context, test bool) (cook.Result, error) {
	url, _ := p.properties["url"].(string)
	base, content, err := aptSource(p.name, url)
	if err != nil {
		return failResult(err)
	}
	path := filepath.Join(aptSourcesDir, base)
	other := strings.TrimSuffix(path, filepath.Ext(path)) + aptOtherExt(filepath.Ext(path))
	cur, err := readFileState(path)
	if err != nil {
		return failResult(err)
	}
	prevOther, err := readFileState(other)
	if err != nil {
		return failResult(err)
	}
	if cur.existed && bytes.Equal(cur.content, content) && !prevOther.existed {
		return cook.Result{
			Succeeded: true,
			Changed:   false,
			Notes:     []fmt.Stringer{note("repository already configured: %s", p.name)},
		}, nil
	}
	verb := "added"
	if cur.existed || prevOther.existed {
		verb = "updated"
	}
	if test {
		return cook.Result{
			Succeeded: true,
			Changed:   true,
			Notes:     []fmt.Stringer{note("would write %s (%s repository %s)", path, verb, p.name)},
		}, nil
	}
	if err := writeFileAtomic(path, content); err != nil {
		return failResult(err)
	}
	if prevOther.existed {
		if err := os.Remove(other); err != nil && !errors.Is(err, os.ErrNotExist) {
			return failResult(errors.Join(err, cur.restore()))
		}
	}
	if err := aptUpdate(ctx); err != nil {
		// Leave apt as it was: a source apt can't read breaks every
		// later apt operation on the sprout, not just this step.
		rerr := errors.Join(cur.restore(), prevOther.restore())
		if rerr != nil {
			rerr = fmt.Errorf("restoring the previous sources: %w", rerr)
		}
		return failResult(errors.Join(fmt.Errorf("apt-get update after writing %s (reverted): %w", path, err), rerr))
	}
	return cook.Result{
		Succeeded: true,
		Changed:   true,
		Notes:     []fmt.Stringer{note("%s repository %s: %s", verb, p.name, path)},
	}, nil
}

func (p Pkg) aptRepoRemoved(ctx context.Context, test bool) (cook.Result, error) {
	if err := checkAptSourceName(p.name); err != nil {
		return failResult(err)
	}
	var present []string
	for _, ext := range []string{aptListExt, aptSourcesExt} {
		path := filepath.Join(aptSourcesDir, p.name+ext)
		if _, err := os.Lstat(path); err == nil {
			present = append(present, path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return failResult(err)
		}
	}
	if len(present) == 0 {
		return cook.Result{
			Succeeded: true,
			Changed:   false,
			Notes:     []fmt.Stringer{note("repository already absent: %s", p.name)},
		}, nil
	}
	if test {
		return cook.Result{
			Succeeded: true,
			Changed:   true,
			Notes:     []fmt.Stringer{note("would remove repository %s: %s", p.name, strings.Join(present, ", "))},
		}, nil
	}
	for i, path := range present {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			// An earlier file may already be gone: say so.
			return cook.Result{Succeeded: false, Failed: true, Changed: i > 0}, err
		}
	}
	// The removal is not rolled back if the update fails: removing a
	// repository that breaks apt-get update is a common reason to run this.
	if err := aptUpdate(ctx); err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: true,
			Notes: []fmt.Stringer{note("removed repository %s: %s", p.name, strings.Join(present, ", "))},
		}, fmt.Errorf("apt-get update after removing repository %s: %w", p.name, err)
	}
	return cook.Result{
		Succeeded: true,
		Changed:   true,
		Notes:     []fmt.Stringer{note("removed repository %s: %s", p.name, strings.Join(present, ", "))},
	}, nil
}
