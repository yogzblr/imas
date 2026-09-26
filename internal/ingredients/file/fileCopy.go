package file

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

var (
	ErrCopyInvalidDirection = errors.New("file.copy direction must be push or pull")
	ErrCopySourceIsDir      = errors.New("file.copy destination must be a directory when source is a directory")
)

// copy implements file.copy: a local filesystem copy (single file, or a
// directory tree filtered by glob/exclude) with optional parent-directory
// creation and marking copied files executable.
//
// "direction" governs which of source/name is the read side and which is
// the write side: imas ingredients execute entirely on the sprout they
// target, so both push and pull operate on paths on that same local
// filesystem -- there is no separate controller-side filesystem for this
// ingredient to reach across, unlike Spot's SSH-based push/pull. "push"
// (the default) reads from source and writes to name, the more common case
// of laying down files already staged locally (e.g. from a mounted share or
// an extracted rootball) onto their destination; "pull" reverses that,
// useful for e.g. copying local content out to a mounted backup path.
func (f File) copy(ctx context.Context, test bool) (cook.Result, error) {
	var notes []fmt.Stringer

	name, ok := f.params["name"].(string)
	if !ok || name == "" {
		return cook.Result{Succeeded: false, Failed: true}, ingredients.ErrMissingName
	}
	source, ok := f.params["source"].(string)
	if !ok || source == "" {
		return cook.Result{Succeeded: false, Failed: true}, ErrMissingSource
	}

	direction, _ := f.params["direction"].(string)
	if direction == "" {
		direction = "push"
	}
	var src, dst string
	switch direction {
	case "push":
		src, dst = source, name
	case "pull":
		src, dst = name, source
	default:
		return cook.Result{Succeeded: false, Failed: true},
			fmt.Errorf("%w: got %q", ErrCopyInvalidDirection, direction)
	}
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)

	glob, _ := f.params["glob"].(string)
	exclude := stringSlice(f.params["exclude"])
	mkdir, _ := f.params["mkdir"].(bool)
	chmodX, _ := f.params["chmod_x"].(bool)

	srcInfo, err := os.Stat(src)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true}, err
	}

	if !srcInfo.IsDir() {
		if dstInfo, dstErr := os.Stat(dst); dstErr == nil && dstInfo.IsDir() {
			dst = filepath.Join(dst, filepath.Base(src))
		}
		changed, copyErr := copyFileWithMode(src, dst, mkdir, chmodX, !test)
		if copyErr != nil {
			return cook.Result{Succeeded: false, Failed: true}, copyErr
		}
		verb := "copied"
		if test {
			verb = "would copy"
		}
		if !changed {
			notes = append(notes, cook.Snprintf("`%s` already matches `%s`", dst, src))
			return cook.Result{Succeeded: true, Failed: false, Changed: false, Notes: notes}, nil
		}
		notes = append(notes, cook.Snprintf("%s `%s` to `%s`", verb, src, dst))
		return cook.Result{Succeeded: true, Failed: false, Changed: true, Notes: notes}, nil
	}

	if dstInfo, dstErr := os.Stat(dst); dstErr == nil && !dstInfo.IsDir() {
		return cook.Result{Succeeded: false, Failed: true}, ErrCopySourceIsDir
	}

	rels, err := listTreeFiles(src, glob, exclude)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true}, err
	}

	anyChanged := false
	for _, rel := range rels {
		srcFile := filepath.Join(src, rel)
		dstFile := filepath.Join(dst, rel)
		changed, copyErr := copyFileWithMode(srcFile, dstFile, true, chmodX, !test)
		if copyErr != nil {
			return cook.Result{Succeeded: false, Failed: true, Notes: notes}, copyErr
		}
		if changed {
			anyChanged = true
			verb := "copied"
			if test {
				verb = "would copy"
			}
			notes = append(notes, cook.Snprintf("%s `%s` to `%s`", verb, srcFile, dstFile))
		}
	}
	if !anyChanged {
		notes = append(notes, cook.Snprintf("`%s` already matches `%s`", dst, src))
	}

	return cook.Result{Succeeded: true, Failed: false, Changed: anyChanged, Notes: notes}, nil
}
