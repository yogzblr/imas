//go:build windows

package winshortcut

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

// shortcutState is the desired or observed state of a .lnk shortcut's
// IWshShortcut properties.
type shortcutState struct {
	TargetPath       string
	Arguments        string
	Description      string
	WorkingDirectory string
	IconLocation     string
	WindowStyle      int
	Hotkey           string
}

// Equal reports whether a and b describe the same shortcut. Path-shaped
// fields are compared case-insensitively and with surrounding whitespace
// trimmed: the shell is known to normalize a shortcut's stored
// TargetPath/WorkingDirectory on save, and an exact byte comparison
// against what imas passed in would report a spurious "changed" on every
// run.
func (a shortcutState) Equal(b shortcutState) bool {
	return strings.EqualFold(strings.TrimSpace(a.TargetPath), strings.TrimSpace(b.TargetPath)) &&
		a.Arguments == b.Arguments &&
		a.Description == b.Description &&
		strings.EqualFold(strings.TrimSpace(a.WorkingDirectory), strings.TrimSpace(b.WorkingDirectory)) &&
		strings.EqualFold(a.IconLocation, b.IconLocation) &&
		a.WindowStyle == b.WindowStyle &&
		strings.EqualFold(a.Hotkey, b.Hotkey)
}

// shortcutBackend abstracts the COM-backed shell automation calls this
// ingredient needs, so tests can substitute an in-memory fake instead of
// touching a real Windows shell and COM apartment.
type shortcutBackend interface {
	// Load reads the current property values of the shortcut at path.
	// Callers are responsible for confirming the file exists first.
	Load(path string) (shortcutState, error)
	// Save creates or overwrites the shortcut at path with state.
	Save(path string, state shortcutState) error
}

// backend is replaceable in tests.
var backend shortcutBackend = oleShortcutBackend{}

// windowStyles maps the ingredient's human-readable window_style values
// to the Win32 show-command constants IWshShortcut.WindowStyle expects
// (SW_SHOWNORMAL, SW_SHOWMAXIMIZED, SW_SHOWMINNOACTIVE).
var windowStyles = map[string]int{
	"normal":    1,
	"maximized": 3,
	"minimized": 7,
}

// parseWindowStyle resolves the window_style param to its Win32
// show-command value, defaulting to "normal" (1) when unset. It also
// accepts the raw numeric value directly.
func parseWindowStyle(params map[string]interface{}) (int, error) {
	raw, ok := winexec.StringParam(params, "window_style")
	if !ok || raw == "" {
		return windowStyles["normal"], nil
	}
	if n, ok := windowStyles[strings.ToLower(raw)]; ok {
		return n, nil
	}
	if n, err := strconv.Atoi(raw); err == nil {
		for _, valid := range windowStyles {
			if valid == n {
				return n, nil
			}
		}
	}
	return 0, fmt.Errorf("%w: %q (want normal, maximized, or minimized)", ErrInvalidWindowStyle, raw)
}

// intParam extracts an integer parameter, accepting either a JSON number
// or a string (recipes may author either).
func intParam(params map[string]interface{}, key string, defaultVal int) int {
	v, ok := params[key]
	if !ok {
		return defaultVal
	}
	switch vt := v.(type) {
	case float64:
		return int(vt)
	case int:
		return vt
	case string:
		if n, err := strconv.Atoi(vt); err == nil {
			return n
		}
	}
	return defaultVal
}

// buildDesiredState turns the recipe's params into the shortcutState
// present() should converge the shortcut file toward.
func buildDesiredState(params map[string]interface{}) (shortcutState, error) {
	target, _ := winexec.StringParam(params, "target")
	if target == "" {
		return shortcutState{}, ErrMissingTarget
	}
	arguments, _ := winexec.StringParam(params, "arguments")
	description, _ := winexec.StringParam(params, "description")
	workingDir, _ := winexec.StringParam(params, "working_dir")
	hotkey, _ := winexec.StringParam(params, "hotkey")

	// IWshShortcut.IconLocation is a single "path,index" string, not two
	// separate properties.
	iconLocation := ""
	if iconPath, ok := winexec.StringParam(params, "icon_location"); ok && iconPath != "" {
		iconLocation = fmt.Sprintf("%s,%d", iconPath, intParam(params, "icon_index", 0))
	}

	windowStyle, err := parseWindowStyle(params)
	if err != nil {
		return shortcutState{}, err
	}

	return shortcutState{
		TargetPath:       target,
		Arguments:        arguments,
		Description:      description,
		WorkingDirectory: workingDir,
		IconLocation:     iconLocation,
		WindowStyle:      windowStyle,
		Hotkey:           hotkey,
	}, nil
}

func (s Shortcut) present(_ context.Context, test bool) (cook.Result, error) {
	name, _ := winexec.StringParam(s.params, "name")
	desired, err := buildDesiredState(s.params)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}

	if _, statErr := os.Stat(name); statErr == nil {
		if current, loadErr := backend.Load(name); loadErr == nil && current.Equal(desired) {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
				cook.Snprintf("shortcut %q already matches the desired state", name),
			}}, nil
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, statErr
	}

	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("shortcut %q would be created or updated", name),
		}}, nil
	}

	if err := backend.Save(name, desired); err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("shortcut %q has been created or updated", name),
	}}, nil
}
