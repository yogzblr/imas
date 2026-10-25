//go:build !unix

package harness

import (
	"context"
	"errors"
)

// lockShared holds nothing: the harness runs on the Linux runner only.
func lockShared(context.Context, string) (func(), error) {
	return nil, errors.New("no flock here")
}
