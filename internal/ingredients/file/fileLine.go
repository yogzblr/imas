package file

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

var (
	ErrLineMissingMode    = errors.New("file.line requires a mode")
	ErrLineInvalidMode    = errors.New("file.line mode must be one of ensure, replace, delete, insert")
	ErrLineMissingMatch   = errors.New("file.line requires match for this mode")
	ErrLineMissingContent = errors.New("file.line requires content for this mode")
	ErrLineInvalidMatch   = errors.New("file.line match is not a valid regular expression")
)

// line implements imas's regex-based single-line file editor. It mirrors
// Salt's file.line/file.replace and, on the sprout-orchestration side,
// Spot's "line" action: it was confirmed net-new against the existing file
// ingredient (which had no line-oriented editing -- only whole-file
// append/prepend/content/contains) before being added here.
func (f File) line(ctx context.Context, test bool) (cook.Result, error) {
	var notes []fmt.Stringer

	name, ok := f.params["name"].(string)
	if !ok || name == "" {
		return cook.Result{Succeeded: false, Failed: true}, ingredients.ErrMissingName
	}
	name = filepath.Clean(name)
	if name == "/" {
		return cook.Result{Succeeded: false, Failed: true}, ErrModifyRoot
	}

	mode, ok := f.params["mode"].(string)
	if !ok || mode == "" {
		return cook.Result{Succeeded: false, Failed: true}, ErrLineMissingMode
	}

	matchStr, _ := f.params["match"].(string)
	content, _ := f.params["content"].(string)
	location, _ := f.params["location"].(string)

	var matchRe *regexp.Regexp
	if matchStr != "" {
		re, err := regexp.Compile(matchStr)
		if err != nil {
			return cook.Result{Succeeded: false, Failed: true}, errors.Join(ErrLineInvalidMatch, err)
		}
		matchRe = re
	}

	switch mode {
	case "ensure", "replace", "insert":
		if content == "" {
			return cook.Result{Succeeded: false, Failed: true}, ErrLineMissingContent
		}
	case "delete":
	default:
		return cook.Result{Succeeded: false, Failed: true},
			fmt.Errorf("%w: got %q", ErrLineInvalidMode, mode)
	}
	if (mode == "replace" || mode == "delete") && matchRe == nil {
		return cook.Result{Succeeded: false, Failed: true}, ErrLineMissingMatch
	}

	original, readErr := os.ReadFile(name)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return cook.Result{Succeeded: false, Failed: true}, ErrFileNotFound
		}
		return cook.Result{Succeeded: false, Failed: true}, readErr
	}
	lines := splitLines(string(original))

	newLines, changed, err := applyLineMode(lines, mode, matchRe, content, location)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true}, err
	}

	if !changed {
		notes = append(notes, cook.Snprintf("file `%s` already satisfies the requested line %s", name, mode))
		return cook.Result{Succeeded: true, Failed: false, Changed: false, Notes: notes}, nil
	}

	if test {
		notes = append(notes, cook.Snprintf("file `%s` would be updated (%s)", name, mode))
		return cook.Result{Succeeded: true, Failed: false, Changed: true, Notes: notes}, nil
	}

	info, statErr := os.Stat(name)
	perm := os.FileMode(0o644)
	if statErr == nil {
		perm = info.Mode().Perm()
	}
	newContent := strings.Join(newLines, "\n")
	if len(newLines) > 0 {
		newContent += "\n"
	}
	if err := os.WriteFile(name, []byte(newContent), perm); err != nil {
		return cook.Result{Succeeded: false, Failed: true}, err
	}
	notes = append(notes, cook.Snprintf("file `%s` updated (%s)", name, mode))
	return cook.Result{Succeeded: true, Failed: false, Changed: true, Notes: notes}, nil
}

// splitLines splits file content into lines without keeping a trailing
// empty element for a final newline.
func splitLines(content string) []string {
	if content == "" {
		return nil
	}
	lines := strings.Split(content, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func applyLineMode(lines []string, mode string, matchRe *regexp.Regexp, content, location string) ([]string, bool, error) {
	switch mode {
	case "ensure":
		for _, l := range lines {
			if l == content {
				return lines, false, nil
			}
		}
		return append(append([]string{}, lines...), content), true, nil

	case "delete":
		out := make([]string, 0, len(lines))
		changed := false
		for _, l := range lines {
			if matchRe.MatchString(l) {
				changed = true
				continue
			}
			out = append(out, l)
		}
		return out, changed, nil

	case "replace":
		out := make([]string, len(lines))
		changed := false
		for i, l := range lines {
			if matchRe.MatchString(l) {
				if l != content {
					changed = true
				}
				out[i] = content
			} else {
				out[i] = l
			}
		}
		return out, changed, nil

	case "insert":
		if location == "" {
			location = "after"
		}
		if matchRe == nil {
			switch location {
			case "start":
				return append([]string{content}, lines...), true, nil
			default:
				return append(append([]string{}, lines...), content), true, nil
			}
		}
		idx := -1
		for i, l := range lines {
			if matchRe.MatchString(l) {
				idx = i
				break
			}
		}
		if idx == -1 {
			return lines, false, fmt.Errorf("%w: no line matched to insert relative to", ErrLineMissingMatch)
		}
		out := make([]string, 0, len(lines)+1)
		insertAt := idx
		if location == "after" {
			insertAt = idx + 1
		}
		out = append(out, lines[:insertAt]...)
		out = append(out, content)
		out = append(out, lines[insertAt:]...)
		return out, true, nil

	default:
		return lines, false, fmt.Errorf("%w: got %q", ErrLineInvalidMode, mode)
	}
}
