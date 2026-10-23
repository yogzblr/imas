package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

// symlink creates a symlink at the given path
//
// the expected outcome is that name is a symlink pointing to target
// if force is true, then name will be replaced if it already exists
// if backupname is set, then name will be backed up to backupname if it already exists
// and force is true, and name is not a symlink
// if makedirs is true, then any missing directories in the path will be created
// if user is set, then the symlink will be owned by that user
// if group is set, then the symlink will be owned by that group
// if mode is set, then the symlink will be set to that mode
// if test is true, then the symlink will not be created, but the result will indicate
// what would have happened
func (f File) symlink(ctx context.Context, test bool) (cook.Result, error) {
	// parameters to implement:
	// "name": "string", "target": "string", "force": "bool", "backupname": "string",
	// "makedirs": "bool", "user": "string", "group": "string", "mode": "string",
	var notes []fmt.Stringer
	name, ok := f.params["name"].(string)
	if !ok {
		return cook.Result{
			Succeeded: false, Failed: true,
		}, ingredients.ErrMissingName
	}
	name = filepath.Clean(name)
	if name == "" {
		return cook.Result{
			Succeeded: false, Failed: true,
		}, ingredients.ErrMissingName
	}
	if name == "/" {
		return cook.Result{
			Succeeded: false, Failed: true,
		}, ErrModifyRoot
	}
	target, ok := f.params["target"].(string)
	if !ok {
		return cook.Result{
			Succeeded: false, Failed: true,
		}, ErrMissingTarget
	}
	target = filepath.Clean(target)
	if target == "" {
		return cook.Result{
			Succeeded: false, Failed: true,
		}, ErrMissingTarget
	}

	// Lstat, not Stat: Stat follows the link, so an existing link (or one
	// whose target is missing) looked absent, and every run after the
	// first failed (UAT I.file.symlink).
	fi, err := os.Lstat(name)
	switch {
	case err == nil && fi.Mode()&os.ModeSymlink != 0:
		current, readErr := os.Readlink(name)
		if readErr != nil {
			return cook.Result{
				Succeeded: false, Failed: true,
			}, readErr
		}
		if filepath.Clean(current) == target {
			notes = append(notes, cook.Snprintf("symlink %s already points to %s", name, target))
			return cook.Result{
				Succeeded: true, Failed: false,
				Changed: false, Notes: notes,
			}, nil
		}
		// A link pointing elsewhere is repointed: replacing a link loses
		// nothing but the old target path.
		if test {
			notes = append(notes, cook.Snprintf("would repoint symlink %s from %s to %s", name, current, target))
			return cook.Result{
				Succeeded: true, Failed: false,
				Changed: true, Notes: notes,
			}, nil
		}
		if err := os.Remove(name); err != nil {
			return cook.Result{
				Succeeded: false, Failed: true,
			}, err
		}
		if err := os.Symlink(target, name); err != nil {
			return cook.Result{
				Succeeded: false, Failed: true,
			}, err
		}
		notes = append(notes, cook.Snprintf("repointed symlink %s from %s to %s", name, current, target))
		return cook.Result{
			Succeeded: true, Failed: false,
			Changed: true, Notes: notes,
		}, nil
	case err == nil:
		return cook.Result{
			Succeeded: false, Failed: true,
		}, fmt.Errorf("%w: %s exists and is not a symlink", ErrPathExists, name)
	case !os.IsNotExist(err):
		return cook.Result{
			Succeeded: false, Failed: true,
		}, err
	}

	dir := filepath.Dir(name)
	if _, dirErr := os.Stat(dir); os.IsNotExist(dirErr) {
		if makedirs, _ := f.params["makedirs"].(bool); !makedirs {
			return cook.Result{
				Succeeded: false, Failed: true,
			}, fmt.Errorf("%w: parent directory %s of %s, and makedirs is false", ErrPathNotFound, dir, name)
		}
		if !test {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return cook.Result{
					Succeeded: false, Failed: true,
				}, err
			}
			notes = append(notes, cook.Snprintf("created directory %s", dir))
		}
	}
	if test {
		notes = append(notes, cook.Snprintf("would create symlink %s pointing to %s", name, target))
		return cook.Result{
			Succeeded: true, Failed: false,
			Changed: true, Notes: notes,
		}, nil
	}
	if err := os.Symlink(target, name); err != nil {
		return cook.Result{
			Succeeded: false, Failed: true,
		}, err
	}
	notes = append(notes, cook.Snprintf("created symlink %s pointing to %s", name, target))
	return cook.Result{
		Succeeded: true, Failed: false,
		Changed: true, Notes: notes,
	}, nil
}
