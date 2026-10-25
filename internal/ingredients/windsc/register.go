//go:build windows

package windsc

import "github.com/yogzblr/imas/internal/ingredients"

// Registration is Windows-only; see the package doc in windsc.go.
func init() {
	ingredients.RegisterAllMethods(Dsc{})
}
