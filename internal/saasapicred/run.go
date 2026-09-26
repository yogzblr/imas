// Package saasapicred implements `farmer publish-saasapi-credential`: a
// one-shot run, meant for a Kubernetes Job using farmer's own image, that
// mints (or confirms) the SaaS API's NATS User JWT via
// pki.EnsureSaaSAPICredential and writes it into OpenBao KV v2, where
// External Secrets Operator picks it up for the saasapi Deployment. See
// deploy/farmer/ for the reference Job and the OpenBao policy it needs,
// and docs/design/imas-internal-api-account.md for why this exists.
//
// It is deliberately a separate process invocation rather than something
// farmer's server does at boot: the OpenBao identity it authenticates as
// (IMAS_SAASAPI_CRED_OPENBAO_*) is the only one with write access to the
// published secret, and farmer's long-running process must never hold it.
//
// This lives outside cmd/farmer only so it can be tested: cmd/farmer's
// init() loads /etc/imas/farmer, which a test binary can't redirect.
//
// FLAG FOR SECURITY REVIEW — see deploy/farmer/README.md.
package saasapicred

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/openbaokv"
	"github.com/yogzblr/imas/internal/pki"
)

// Command is the farmer subcommand name cmd/farmer dispatches on.
const Command = "publish-saasapi-credential"

// EnvKVPath names the KV v2 secret path (relative to
// IMAS_SAASAPI_CRED_OPENBAO_KV_MOUNT) the JWT is written to. Required —
// either this or -kv-path — with no built-in default, since the path is
// what the Job's OpenBao policy is scoped to.
const EnvKVPath = "IMAS_SAASAPI_CRED_OPENBAO_KV_PATH"

// Run parses args (everything after the subcommand name), mints and
// publishes the credential, and returns the process exit code: 0 on
// success (written or already current), 1 if minting or publishing
// failed, 2 for a usage/configuration error.
func Run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("farmer "+Command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	kvPath := fs.String("kv-path", os.Getenv(EnvKVPath),
		"KV v2 secret path to write the SaaS API NATS User JWT to, relative to the KV mount (env "+EnvKVPath+")")
	timeout := fs.Duration("timeout", 2*time.Minute, "overall deadline for minting and publishing")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: farmer %s [flags]\n\n", Command)
		fmt.Fprintf(stderr, "Mints the SaaS API's NATS User JWT and publishes it to OpenBao KV v2.\n")
		fmt.Fprintf(stderr, "OpenBao connection/auth: %s, %s, %s, %s, ...\n\n",
			openbaokv.EnvOpenBaoAddr, openbaokv.EnvOpenBaoKVMount, openbaokv.EnvOpenBaoAuthMethod, openbaokv.EnvOpenBaoK8sRole)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		fs.Usage()
		return 2
	}
	if *kvPath == "" {
		fmt.Fprintf(stderr, "a KV path is required: set -kv-path or %s\n", EnvKVPath)
		return 2
	}

	client, err := openbaokv.NewClientFromEnv()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	secret, err := client.At(*kvPath)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	res, err := pki.PublishSaaSAPICredential(ctx, secret)
	if res.PublicKey != "" {
		if res.Written {
			log.Infof("Published the SaaS API NATS User JWT for %s to %s/data/%s.", res.PublicKey, client.Mount(), secret.Path())
		} else {
			log.Infof("SaaS API NATS User JWT for %s at %s/data/%s is already current; nothing written.", res.PublicKey, client.Mount(), secret.Path())
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", Command, err)
		return 1
	}
	return 0
}
