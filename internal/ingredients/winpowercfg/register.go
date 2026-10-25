//go:build windows

package winpowercfg

import "github.com/yogzblr/imas/internal/ingredients"

// Registration is Windows-only; see scheme.go.
func init() {
	ingredients.RegisterAllMethods(Scheme{})
}
