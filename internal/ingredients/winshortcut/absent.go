//go:build windows

package winshortcut

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

// absent removes the shortcut file at name. It never touches COM: a
// missing or present .lnk is a plain filesystem fact, so this path has
// none of the apartment/lifecycle concerns present.go's COM calls do.
func (s Shortcut) absent(_ context.Context, test bool) (cook.Result, error) {
	name, _ := winexec.StringParam(s.params, "name")

	if _, err := os.Stat(name); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
				cook.Snprintf("shortcut %q is already absent", name),
			}}, nil
		}
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}

	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("shortcut %q would be removed", name),
		}}, nil
	}

	if err := os.Remove(name); err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("shortcut %q has been removed", name),
	}}, nil
}
