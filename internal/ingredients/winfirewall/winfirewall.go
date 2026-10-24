//go:build windows

package winfirewall

import "github.com/yogzblr/imas/internal/ingredients"

// Registration is Windows-only; see the package doc in rule.go.
func init() {
	ingredients.RegisterAllMethods(Rule{})
}
