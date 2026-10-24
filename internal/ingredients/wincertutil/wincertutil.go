//go:build windows

package wincertutil

import "github.com/yogzblr/imas/internal/ingredients"

// Registration is Windows-only; see the package doc in cert.go.
func init() {
	ingredients.RegisterAllMethods(Cert{})
}
