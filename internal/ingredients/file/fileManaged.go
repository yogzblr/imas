package file

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

// ErrInvalidMode is returned for a mode that is not an octal permission
// string such as "640" or "0644".
var ErrInvalidMode = errors.New("invalid file mode")

// parseManagedMode reads managed's mode property: an octal permission
// string, at most 07777. ok is false when no mode is set. The mode is
// ignored on Windows, where os.Chmod only toggles the read-only flag and the
// permission bits can't be read back.
func parseManagedMode(params map[string]interface{}) (mode os.FileMode, ok bool, err error) {
	s, _ := params["mode"].(string)
	if s == "" || runtime.GOOS == "windows" {
		return 0, false, nil
	}
	v, perr := strconv.ParseUint(s, 8, 32)
	if perr != nil || v > 0o7777 {
		return 0, false, fmt.Errorf("%w: %q (an octal permission such as 0644)", ErrInvalidMode, s)
	}
	mode = os.FileMode(v & 0o777)
	if v&0o4000 != 0 {
		mode |= os.ModeSetuid
	}
	if v&0o2000 != 0 {
		mode |= os.ModeSetgid
	}
	if v&0o1000 != 0 {
		mode |= os.ModeSticky
	}
	return mode, true, nil
}

// sameContent reports whether the two files hold the same bytes.
func sameContent(a, b string) (bool, error) {
	fa, err := os.Open(a)
	if err != nil {
		return false, err
	}
	defer fa.Close()
	fb, err := os.Open(b)
	if err != nil {
		return false, err
	}
	defer fb.Close()
	sa, err := fa.Stat()
	if err != nil {
		return false, err
	}
	sb, err := fb.Stat()
	if err != nil {
		return false, err
	}
	if sa.Size() != sb.Size() {
		return false, nil
	}
	bufA, bufB := make([]byte, 32*1024), make([]byte, 32*1024)
	for {
		na, errA := io.ReadFull(fa, bufA)
		nb, errB := io.ReadFull(fb, bufB)
		if na != nb || !bytes.Equal(bufA[:na], bufB[:nb]) {
			return false, nil
		}
		endA := errors.Is(errA, io.EOF) || errors.Is(errA, io.ErrUnexpectedEOF)
		endB := errors.Is(errB, io.EOF) || errors.Is(errB, io.ErrUnexpectedEOF)
		if errA != nil && !endA {
			return false, errA
		}
		if errB != nil && !endB {
			return false, errB
		}
		if endA || endB {
			return endA && endB, nil
		}
	}
}

// managedMatches reports whether name already holds the cached source's
// content and, when a mode is wanted, that mode: nothing to do.
func managedMatches(name, cached string, mode os.FileMode, haveMode bool) (contentOK, modeOK bool) {
	st, err := os.Stat(name)
	if err != nil {
		return false, false
	}
	same, err := sameContent(name, cached)
	contentOK = err == nil && same
	modeOK = !haveMode || st.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == mode
	return contentOK, modeOK
}

func (f File) managed(ctx context.Context, test bool) (cook.Result, error) {
	// Params: "name", "source", "source_hash", "user", "group", "mode", "attrs",
	// "template", "makedirs", "dir_mode", "replace", "backup", "show_changes",
	// "create", "follow_symlinks", "skip_verify"

	var notes []fmt.Stringer

	name, ok := f.params["name"].(string)
	if !ok || name == "" {
		return cook.Result{
			Succeeded: false, Failed: true,
			Changed: false, Notes: []fmt.Stringer{},
		}, ingredients.ErrMissingName
	}
	name = filepath.Clean(name)
	if name == "/" {
		return cook.Result{
			Succeeded: false, Failed: true,
			Changed: false, Notes: []fmt.Stringer{},
		}, ErrModifyRoot
	}

	wantMode, haveMode, err := parseManagedMode(f.params)
	if err != nil {
		return cook.Result{
			Succeeded: false, Failed: true,
			Changed: false, Notes: []fmt.Stringer{},
		}, err
	}

	source, _ := f.params["source"].(string)
	sourceHash, _ := f.params["source_hash"].(string)
	skipVerify, _ := f.params["skip_verify"].(bool)
	makedirs, _ := f.params["makedirs"].(bool)
	create := true // default: create if missing
	if c, ok := f.params["create"].(bool); ok {
		create = c
	}
	backup, _ := f.params["backup"].(string)
	_ = backup

	// Validate source hash requirement
	if source != "" && sourceHash == "" && !skipVerify {
		return cook.Result{
			Succeeded: false, Failed: true,
			Changed: false, Notes: []fmt.Stringer{},
		}, ErrMissingHash
	}

	// Ensure parent directory exists
	dir := filepath.Dir(name)
	if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
		if !makedirs {
			return cook.Result{
				Succeeded: false, Failed: true,
				Changed: false, Notes: []fmt.Stringer{
					cook.Snprintf("parent directory `%s` does not exist and makedirs is false", dir),
				},
			}, ErrPathNotFound
		}
		if test {
			notes = append(notes, cook.Snprintf("directory `%s` would be created", dir))
		} else {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return cook.Result{
					Succeeded: false, Failed: true,
					Changed: false, Notes: notes,
				}, err
			}
			notes = append(notes, cook.Snprintf("created directory `%s`", dir))
		}
	}

	// Check if file exists
	_, statErr := os.Stat(name)
	fileExists := statErr == nil

	if !fileExists && !create {
		return cook.Result{
			Succeeded: true, Failed: false,
			Changed: false, Notes: []fmt.Stringer{
				cook.Snprintf("file `%s` does not exist and create is false", name),
			},
		}, nil
	}

	// Cache the source file if provided
	if source == "" {
		return cook.Result{
			Succeeded: false, Failed: true,
			Changed: false, Notes: []fmt.Stringer{},
		}, ErrMissingSource
	}

	cachedName := fmt.Sprintf("%s-source", f.id)
	cacheParams := map[string]interface{}{
		"source":      source,
		"skip_verify": skipVerify,
		"name":        cachedName,
	}
	if sourceHash != "" {
		cacheParams["hash"] = sourceHash
	}

	cacheFile, err := f.Parse(cachedName, "cached", cacheParams)
	if err != nil {
		notes = append(notes, cook.Snprintf("failed to parse cache for source `%s`", source))
		return cook.Result{
			Succeeded: false, Failed: true,
			Changed: false, Notes: notes,
		}, err
	}

	if test {
		cacheRes, err := cacheFile.Test(ctx)
		notes = append(notes, cacheRes.Notes...)
		if err != nil || !cacheRes.Succeeded {
			return cook.Result{
				Succeeded: false, Failed: true,
				Changed: false, Notes: notes,
			}, errors.Join(err, ErrCacheFailure)
		}
		changed := true
		if fileExists {
			note := cook.Snprintf("file `%s` would be updated from source", name)
			// The source may already be cached (an earlier cook): then
			// compare, and report what an apply would do.
			if cf, ok := cacheFile.(File); ok {
				if cached, derr := cf.dest(); derr == nil {
					contentOK, modeOK := managedMatches(name, cached, wantMode, haveMode)
					switch {
					case contentOK && modeOK:
						changed = false
						note = cook.Snprintf("file `%s` already matches source `%s`", name, source)
					case contentOK:
						note = cook.Snprintf("mode of file `%s` would be set to %04o", name, wantMode.Perm())
					}
				}
			}
			notes = append(notes, note)
		}
		return cook.Result{
			Succeeded: true, Failed: false,
			Changed: changed, Notes: notes,
		}, nil
	}

	// Apply: download/cache the source
	cacheRes, err := cacheFile.Apply(ctx)
	notes = append(notes, cacheRes.Notes...)
	if err != nil || !cacheRes.Succeeded {
		return cook.Result{
			Succeeded: false, Failed: true,
			Changed: false, Notes: notes,
		}, errors.Join(err, ErrCacheFailure)
	}

	// Get the cached file path
	cf := cacheFile.(File)
	sourceDest, err := cf.dest()
	if err != nil {
		notes = append(notes, cook.Snprintf("failed to get cached source destination: %v", err))
		return cook.Result{
			Succeeded: false, Failed: true,
			Changed: false, Notes: notes,
		}, err
	}

	// Nothing to do when the destination already holds the source's content
	// and mode. A mode that differs alone is fixed without rewriting the
	// content.
	if fileExists {
		contentOK, modeOK := managedMatches(name, sourceDest, wantMode, haveMode)
		if contentOK {
			if modeOK {
				notes = append(notes, cook.Snprintf("file `%s` already matches source `%s`", name, source))
				return cook.Result{
					Succeeded: true, Failed: false,
					Changed: false, Notes: notes,
				}, nil
			}
			if err := os.Chmod(name, wantMode); err != nil {
				return cook.Result{
					Succeeded: false, Failed: true,
					Changed: false, Notes: notes,
				}, err
			}
			notes = append(notes, cook.Snprintf("mode of file `%s` set to %04o", name, wantMode.Perm()))
			return cook.Result{
				Succeeded: true, Failed: false,
				Changed: true, Notes: notes,
			}, nil
		}
	}

	// Copy cached source to destination
	srcFile, err := os.Open(sourceDest)
	if err != nil {
		return cook.Result{
			Succeeded: false, Failed: true,
			Changed: false, Notes: notes,
		}, err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(name)
	if err != nil {
		return cook.Result{
			Succeeded: false, Failed: true,
			Changed: false, Notes: notes,
		}, err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return cook.Result{
			Succeeded: false, Failed: true,
			Changed: false, Notes: notes,
		}, err
	}
	if haveMode {
		// Chmod, not the create mode: the umask must not narrow it.
		if err := os.Chmod(name, wantMode); err != nil {
			return cook.Result{
				Succeeded: false, Failed: true,
				Changed: false, Notes: notes,
			}, err
		}
	}

	notes = append(notes, cook.Snprintf("file `%s` managed from source `%s`", name, source))
	return cook.Result{
		Succeeded: true, Failed: false,
		Changed: true, Notes: notes,
	}, nil
}
