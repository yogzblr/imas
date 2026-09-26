package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

// sync implements file.sync: a one-way local directory sync (source into
// name), with optional orphan deletion and exclude patterns. Like
// file.copy, this operates entirely on the sprout's own local filesystem.
func (f File) sync(ctx context.Context, test bool) (cook.Result, error) {
	var notes []fmt.Stringer

	name, ok := f.params["name"].(string)
	if !ok || name == "" {
		return cook.Result{Succeeded: false, Failed: true}, ingredients.ErrMissingName
	}
	source, ok := f.params["source"].(string)
	if !ok || source == "" {
		return cook.Result{Succeeded: false, Failed: true}, ErrMissingSource
	}
	name = filepath.Clean(name)
	source = filepath.Clean(source)

	if _, err := os.Stat(source); err != nil {
		return cook.Result{Succeeded: false, Failed: true}, err
	}

	deleteOrphans, _ := f.params["delete"].(bool)
	exclude := stringSlice(f.params["exclude"])
	mkdir, _ := f.params["mkdir"].(bool)

	if info, err := os.Stat(name); os.IsNotExist(err) {
		if !mkdir {
			return cook.Result{Succeeded: false, Failed: true}, ErrPathNotFound
		}
		if !test {
			if err := os.MkdirAll(name, 0o755); err != nil {
				return cook.Result{Succeeded: false, Failed: true}, err
			}
		}
		notes = append(notes, cook.Snprintf("directory `%s` created", name))
	} else if err == nil && !info.IsDir() {
		return cook.Result{Succeeded: false, Failed: true}, ErrCopySourceIsDir
	}

	wanted, err := listTreeFiles(source, "", exclude)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true}, err
	}
	wantedSet := make(map[string]bool, len(wanted))
	for _, rel := range wanted {
		wantedSet[rel] = true
	}

	anyChanged := false
	for _, rel := range wanted {
		changed, copyErr := copyFileWithMode(filepath.Join(source, rel), filepath.Join(name, rel), true, false, !test)
		if copyErr != nil {
			return cook.Result{Succeeded: false, Failed: true, Notes: notes}, copyErr
		}
		if changed {
			anyChanged = true
			verb := "synced"
			if test {
				verb = "would sync"
			}
			notes = append(notes, cook.Snprintf("%s `%s`", verb, filepath.Join(name, rel)))
		}
	}

	if deleteOrphans {
		existing, err := listTreeFiles(name, "", nil)
		if err != nil && !os.IsNotExist(err) {
			return cook.Result{Succeeded: false, Failed: true, Notes: notes}, err
		}
		for _, rel := range existing {
			if wantedSet[rel] {
				continue
			}
			anyChanged = true
			target := filepath.Join(name, rel)
			if test {
				notes = append(notes, cook.Snprintf("would remove orphan `%s`", target))
				continue
			}
			if err := os.Remove(target); err != nil {
				return cook.Result{Succeeded: false, Failed: true, Notes: notes}, err
			}
			notes = append(notes, cook.Snprintf("removed orphan `%s`", target))
		}
	}

	if !anyChanged {
		notes = append(notes, cook.Snprintf("`%s` already in sync with `%s`", name, source))
	}

	return cook.Result{Succeeded: true, Failed: false, Changed: anyChanged, Notes: notes}, nil
}
