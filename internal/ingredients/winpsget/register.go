//go:build windows

package winpsget

import "github.com/yogzblr/imas/internal/ingredients"

// Registration is Windows-only; see the package doc in winpsget.go.
func init() {
	ingredients.RegisterAllMethods(PSGet{})
}
