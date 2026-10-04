package pki

// `farmer ensure-controlplane-box-keys`: the Helm hook Job that creates
// the platform keypair and the SaaS API's box keypair in OpenBao, and
// publishes their public halves for each end to pin (platformbox.go's
// file comment has the layout). FLAG FOR SECURITY REVIEW.
//
// It runs under an OpenBao identity of its own (IMAS_CPBOX_OPENBAO_*,
// role imas-controlplane-box-keygen), never farmer's: that role may
// create and read the two keypairs, and create, read and update the
// public secret, nothing else. Without update on the keypairs it can't
// overwrite one, so a re-run (every helm upgrade) never replaces a key:
// it creates what's missing, and rewrites the public secret only when it
// doesn't match the keypairs. Rotating either key is a separate,
// deliberate act (Open question 4), not something an upgrade can do.
//
// The private halves exist in this process only between generation and
// the write, and are never printed: the Job logs fingerprints.
//
// cmd/farmer dispatches to RunControlPlaneBoxKeys on ControlPlaneBoxKeysCommand
// before it loads any config, as it does register-sprout-release
// (cmd/farmer/subcommands.go). The chart's Job stays off by default
// (controlPlaneBoxKeys.enabled) until rollout step 5 gives the keys a
// consumer.

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/openbao"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// ControlPlaneBoxKeysCommand is the farmer subcommand name.
const ControlPlaneBoxKeysCommand = "ensure-controlplane-box-keys"

// The Job's OpenBao identity, separate from farmer's tenantbox one.
const (
	EnvCPBoxOpenBaoAddr       = "IMAS_CPBOX_OPENBAO_ADDR"
	EnvCPBoxOpenBaoKVMount    = "IMAS_CPBOX_OPENBAO_KV_MOUNT" // default "secret"
	EnvCPBoxOpenBaoKVPath     = "IMAS_CPBOX_OPENBAO_KV_PATH"  // the tenant box base path; default "imas/tenant-x25519"
	EnvCPBoxOpenBaoCACert     = "IMAS_CPBOX_OPENBAO_CACERT"
	EnvCPBoxOpenBaoAuthMethod = "IMAS_CPBOX_OPENBAO_AUTH_METHOD"
	EnvCPBoxOpenBaoToken      = "IMAS_CPBOX_OPENBAO_TOKEN"
	EnvCPBoxOpenBaoK8sRole    = "IMAS_CPBOX_OPENBAO_K8S_ROLE"
	EnvCPBoxOpenBaoK8sMount   = "IMAS_CPBOX_OPENBAO_K8S_MOUNT"
	EnvCPBoxOpenBaoK8sJWTPath = "IMAS_CPBOX_OPENBAO_K8S_JWT_PATH"
	EnvCPBoxOpenBaoNamespace  = "IMAS_CPBOX_OPENBAO_NAMESPACE"
)

var cpBoxOpenBaoEnv = openbao.Env{
	Addr:       EnvCPBoxOpenBaoAddr,
	CACert:     EnvCPBoxOpenBaoCACert,
	AuthMethod: EnvCPBoxOpenBaoAuthMethod,
	Token:      EnvCPBoxOpenBaoToken,
	K8sRole:    EnvCPBoxOpenBaoK8sRole,
	K8sMount:   EnvCPBoxOpenBaoK8sMount,
	K8sJWTPath: EnvCPBoxOpenBaoK8sJWTPath,
	Namespace:  EnvCPBoxOpenBaoNamespace,
}

// ErrCPBoxNotConfigured: the Job's OpenBao identity isn't configured.
var ErrCPBoxNotConfigured = errors.New("pki: control-plane keygen OpenBao client not configured")

func newCPBoxClientFromEnv() (*obKVClient, error) {
	ob, err := openbao.NewFromEnv(cpBoxOpenBaoEnv, openbao.Errors{NotConfigured: ErrCPBoxNotConfigured})
	if err != nil {
		return nil, err
	}
	mount := os.Getenv(EnvCPBoxOpenBaoKVMount)
	if mount == "" {
		mount = "secret"
	}
	path := os.Getenv(EnvCPBoxOpenBaoKVPath)
	if path == "" {
		path = "imas/tenant-x25519"
	}
	return &obKVClient{ob: ob, mount: mount, path: strings.Trim(path, "/")}, nil
}

// ControlPlaneBoxKeys reports what EnsureControlPlaneBoxKeys found or
// made: public halves only.
type ControlPlaneBoxKeys struct {
	PlatformPub, SaaSAPIBoxPub   string
	PlatformCreated, SaaSCreated bool
	PublicWritten                bool
}

// ensureKeypair returns the current keypair at path, creating it
// (check-and-set 0, origin controlPlaneOriginJob) if it was never written.
func (c *obKVClient) ensureKeypair(ctx context.Context, path string) (key *tenantBoxKey, created bool, err error) {
	key, found, err := c.readKeypair(ctx, path, 0)
	if err != nil || found {
		return key, false, err
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, err
	}
	written, err := c.writeKeypair(ctx, path, pub, priv, 0, map[string]string{"origin": controlPlaneOriginJob})
	wipe(priv[:])
	if err != nil {
		// No update capability: a 403 here means someone else created
		// it between the read and the write. Re-read either way.
		if openbao.StatusCode(err) != 403 {
			return nil, false, err
		}
	}
	key, found, err = c.readKeypair(ctx, path, 0)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, fmt.Errorf("pki: %s not readable after creating it (is its current version deleted in OpenBao?)", path)
	}
	return key, written, nil
}

// EnsureControlPlaneBoxKeys creates the platform and SaaS API box
// keypairs if missing, and makes the public secret name their current
// public halves.
func EnsureControlPlaneBoxKeys(ctx context.Context) (*ControlPlaneBoxKeys, error) {
	c, err := newCPBoxClientFromEnv()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	platform, pCreated, err := c.ensureKeypair(ctx, c.secretPath(platformBoxSecret))
	if err != nil {
		return nil, fmt.Errorf("platform keypair: %w", err)
	}
	wipe(platform.priv[:])
	saas, sCreated, err := c.ensureKeypair(ctx, c.secretPath(saasapiBoxSecret))
	if err != nil {
		return nil, fmt.Errorf("SaaS API box keypair: %w", err)
	}
	wipe(saas.priv[:])
	if *platform.pub == *saas.pub {
		return nil, errors.New("pki: the platform and SaaS API box keys are the same key; refusing to publish them")
	}
	out := &ControlPlaneBoxKeys{
		PlatformPub: encodeBoxPub(platform.pub), SaaSAPIBoxPub: encodeBoxPub(saas.pub),
		PlatformCreated: pCreated, SaaSCreated: sCreated,
	}
	want := map[string]string{controlPlanePubField: out.PlatformPub, controlPlaneSaaSField: out.SaaSAPIBoxPub}
	path := c.secretPath(controlPlanePubSecret)
	data, ver, _, found, err := c.readFields(ctx, path, 0)
	if err != nil {
		return nil, err
	}
	if found && data[controlPlanePubField] == want[controlPlanePubField] && data[controlPlaneSaaSField] == want[controlPlaneSaaSField] {
		return out, nil
	}
	written, err := c.writeFields(ctx, path, want, ver)
	if err != nil {
		return nil, fmt.Errorf("public keys: %w", err)
	}
	if !written {
		return nil, errors.New("pki: the control-plane public key secret changed while it was being written; run the Job again")
	}
	out.PublicWritten = true
	return out, nil
}

// RunControlPlaneBoxKeys runs the Job: args are everything after the
// subcommand name. Exit code 0 on success, 1 on failure, 2 for usage.
func RunControlPlaneBoxKeys(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("farmer "+ControlPlaneBoxKeysCommand, flag.ContinueOnError)
	fs.SetOutput(stderr)
	timeout := fs.Duration("timeout", 2*time.Minute, "overall deadline")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	res, err := EnsureControlPlaneBoxKeys(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", ControlPlaneBoxKeysCommand, err)
		if errors.Is(err, ErrCPBoxNotConfigured) {
			return 2
		}
		return 1
	}
	for _, k := range []struct {
		name, pub string
		created   bool
	}{{"platform", res.PlatformPub, res.PlatformCreated}, {"saasapi box", res.SaaSAPIBoxPub, res.SaaSCreated}} {
		state := "present"
		if k.created {
			state = "created"
		}
		pub, _ := decodeBoxKeyHalf(k.pub)
		fmt.Fprintf(stderr, "%s key %s: %s\n", k.name, state, payloadbox.Fingerprint(pub))
	}
	if res.PublicWritten {
		fmt.Fprintf(stderr, "public keys published to %s\n", controlPlanePubSecret)
	}
	return 0
}
