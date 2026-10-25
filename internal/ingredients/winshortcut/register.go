//go:build windows

package winshortcut

import "github.com/yogzblr/imas/internal/ingredients"

// Registration is Windows-only; see the package doc in winshortcut.go.
func init() {
	ingredients.RegisterAllMethods(Shortcut{})
}
