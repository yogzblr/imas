package main

import (
	"io"

	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/sproutrelease"
)

// runPreConfigSubcommand runs a one-shot subcommand that needs no farmer
// config, PKI directory or log setup, and so runs before LoadConfig, which
// would create /etc/imas on a hook Job's read-only root. ok is false when
// args names none of them, and main goes on to start the server.
//
//   - register-sprout-release: the Helm chart's sprout release hook
//     (internal/sproutrelease).
//   - ensure-controlplane-box-keys: the chart's control-plane keygen hook
//     (internal/pki controlplanekeys.go, J.1). FLAG FOR SECURITY REVIEW.
//     It reads only its own IMAS_CPBOX_OPENBAO_* environment.
func runPreConfigSubcommand(args []string, stdout, stderr io.Writer) (code int, ok bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch args[0] {
	case sproutrelease.Command:
		return sproutrelease.Run(args[1:], stdout, stderr), true
	case pki.ControlPlaneBoxKeysCommand:
		return pki.RunControlPlaneBoxKeys(args[1:], stderr), true
	}
	return 0, false
}
