// Package natsbootstrap implements `farmer bootstrap-nats-trust`, the
// nats-trust init container of the chart's OpenBao bootstrap Job (P21
// slice 1, docs/briefs/P21-slice1-transit-signer.md §4.2). It creates the
// three platform NATS keys in OpenBao Transit, mints the public trust
// chain from them with pki.BootstrapNATSTrust and writes it to the
// ConfigMap imas-nats-trust, which farmer and the bus mount. With
// IMAS_NATSBOOT_BUS_CA_CONFIGMAP set it also writes the certificate of
// the PKI mount's issuer (<mount>/cert/ca, the issuing_ca of every
// certificate the bus's role issues) to that ConfigMap as ca.crt, the CA
// the bus's account loader verifies its node with (unit S1).
//
// It runs as the identity IMAS_NATSBOOT_OPENBAO_*, with a short-lived
// token the Job's prepare container minted for the ephemeral policy
// imas-nats-bootstrap and handed over in a memory-backed file
// (IMAS_NATSBOOT_OPENBAO_TOKEN_FILE). That token is the only one that
// may sign with the operator identity key; this command revokes it
// (auth/token/revoke-self) and removes the file before it exits, whether
// or not the run succeeded.
//
// Without a token file it only checks: the ConfigMap must be complete
// and valid, and match Transit when an OpenBao identity is configured.
// Nothing is created or written.
//
// Every step is idempotent: a re-run over its own output creates no key,
// signs nothing and writes nothing. It never replaces an existing trust
// anchor (pki.ErrTrustWouldChange).
//
// cmd/farmer dispatches here before loading any config, as it does
// ensure-controlplane-box-keys (cmd/farmer/subcommands.go); this package
// lives outside cmd/farmer so it can be tested.
//
// FLAG FOR SECURITY REVIEW: this command holds the operator identity
// signing permission and writes the trust anchor of every NATS
// connection.
package natsbootstrap

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/openbao"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/natskeys"
)

// Command is the farmer subcommand name cmd/farmer dispatches on.
const Command = "bootstrap-nats-trust"

// Environment, besides natskeys's IMAS_NATSBOOT_OPENBAO_* block.
const (
	// EnvTokenFile names the handoff file holding the bootstrap token.
	// When the file is absent the command only checks.
	EnvTokenFile = natskeys.EnvPrefixBoot + "OPENBAO_TOKEN_FILE"
	// EnvTrustConfigMap is the trust ConfigMap's name in the pod's
	// namespace; default DefaultTrustConfigMap.
	EnvTrustConfigMap = natskeys.EnvPrefixBoot + "TRUST_CONFIGMAP"
	// EnvOperatorName is the operator JWT's name when it is first
	// minted; default DefaultOperatorName.
	EnvOperatorName = natskeys.EnvPrefixBoot + "OPERATOR_NAME"
	// EnvBusFenceUserPub is the bus fence user's public NKey; when set, a
	// fence user JWT for it is minted (signed by the SYS account key).
	EnvBusFenceUserPub = natskeys.EnvPrefixBoot + "BUS_FENCE_USER_PUB"
	// EnvBusLoaderUserPub is the bus account loader's public NKey; when
	// set, a loader user JWT for it is minted (signed by the SYS account
	// key, with exactly pki.BusLoaderUserPermissions).
	EnvBusLoaderUserPub = natskeys.EnvPrefixBoot + "BUS_LOADER_USER_PUB"
	// EnvKVCopy set to "true" also copies the public trust to OpenBao KV
	// v2 at EnvKVMount/EnvKVPath. Default off.
	EnvKVCopy  = natskeys.EnvPrefixBoot + "KV_COPY"
	EnvKVMount = natskeys.EnvPrefixBoot + "OPENBAO_KV_MOUNT" // default "secret"
	EnvKVPath  = natskeys.EnvPrefixBoot + "OPENBAO_KV_PATH"  // default DefaultKVPath
	// EnvBusCAConfigMap names the ConfigMap, in the pod's namespace, that
	// gets the bus's CA certificate as BusCAKey. Unset: no such step.
	EnvBusCAConfigMap = natskeys.EnvPrefixBoot + "BUS_CA_CONFIGMAP"
	// EnvBusCAPKIMount is the PKI mount the bus's role issues from.
	// Required with EnvBusCAConfigMap.
	EnvBusCAPKIMount = natskeys.EnvPrefixBoot + "BUS_CA_PKI_MOUNT"
)

// BusCAKey is the bus CA ConfigMap's one key the nats chart projects.
const BusCAKey = "ca.crt"

// Defaults for the variables above.
const (
	DefaultTrustConfigMap = "imas-nats-trust"
	DefaultOperatorName   = "imas-operator"
	DefaultKVMount        = "secret"
	DefaultKVPath         = "platform/imas/nats-trust"
)

// conflictRetries is how many times a write that lost a race (409) is
// retried after re-reading and re-merging the ConfigMap.
const conflictRetries = 3

// errUsage marks a configuration error: exit code 2.
var errUsage = errors.New("configuration error")

// kvPathMatcher is a KV path of plain segments: no "..", no empty
// segment, nothing that leaves the mount.
var kvPathMatcher = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*(/[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*)*$`)

// platformKeys are the Transit keys the bootstrap creates.
var platformKeys = []struct {
	name   string
	prefix natskeys.Prefix
}{
	{natskeys.OperatorKey(), nkeys.PrefixByteOperator},
	{natskeys.OperatorSigningKey(), nkeys.PrefixByteOperator},
	{natskeys.SysAccountKey(), nkeys.PrefixByteAccount},
}

// Run parses args (everything after the subcommand name), runs the
// bootstrap or the check, and returns the exit code: 0 on success, 1 on
// failure, 2 for a usage or configuration error.
func Run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("farmer "+Command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	timeout := fs.Duration("timeout", 5*time.Minute, "overall deadline")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: farmer %s [flags]\n\n", Command)
		fmt.Fprintf(stderr, "Creates the platform NATS keys in OpenBao Transit and writes the public trust ConfigMap.\n")
		fmt.Fprintf(stderr, "Environment: %s, %s, %s%s, ...\n\n",
			EnvTokenFile, EnvTrustConfigMap, natskeys.EnvPrefixBoot, natskeys.EnvOpenBaoAddr)
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
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := run(ctx, stderr); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", Command, err)
		if errors.Is(err, errUsage) {
			return 2
		}
		return 1
	}
	return 0
}

func run(ctx context.Context, out io.Writer) (err error) {
	tokenFile := os.Getenv(EnvTokenFile)
	token, haveToken, err := readTokenFile(tokenFile)
	if err != nil {
		return err
	}
	if haveToken {
		// The file goes on every return from here, a configuration
		// error included: this is an init container, so when it fails
		// the main container (which revokes by accessor) never runs.
		defer func() {
			if rmErr := os.Remove(tokenFile); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("removing the bootstrap token file: %w", rmErr))
			}
		}()
	}
	cmName := os.Getenv(EnvTrustConfigMap)
	if cmName == "" {
		cmName = DefaultTrustConfigMap
	}
	if !configMapNameMatcher.MatchString(cmName) {
		return fmt.Errorf("%w: %s=%q is not a valid ConfigMap name", errUsage, EnvTrustConfigMap, cmName)
	}
	if !haveToken {
		kube, err := inClusterKube()
		if err != nil {
			return fmt.Errorf("%w: %w", errUsage, err)
		}
		defer kube.close()
		return check(ctx, out, kube, cmName)
	}

	tokenEnv := natskeys.EnvPrefixBoot + natskeys.EnvOpenBaoToken
	methodEnv := natskeys.EnvPrefixBoot + natskeys.EnvOpenBaoAuthMethod
	if os.Getenv(tokenEnv) != "" {
		return fmt.Errorf("%w: both %s and %s are set; the bootstrap token comes from the file only", errUsage, tokenEnv, EnvTokenFile)
	}
	if m := os.Getenv(methodEnv); m != "" && m != openbao.AuthMethodToken {
		return fmt.Errorf("%w: %s=%q, but the bootstrap token file needs token auth", errUsage, methodEnv, m)
	}
	// natskeys and internal/openbao read the token from the environment.
	// This process is one short run, and the variable goes when it ends.
	if err := os.Setenv(tokenEnv, token); err != nil {
		return err
	}
	defer os.Unsetenv(tokenEnv)

	cfg, err := natskeys.ConfigFromEnv(natskeys.EnvPrefixBoot, os.Getenv)
	if err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	ob, err := openbao.NewFromEnv(cfg.OpenBao, openbao.Errors{NotConfigured: natskeys.ErrNotConfigured})
	if err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	defer ob.Close()

	err = func() error {
		kube, err := inClusterKube()
		if err != nil {
			return fmt.Errorf("%w: %w", errUsage, err)
		}
		defer kube.close()
		return bootstrap(ctx, out, kube, cmName, cfg, ob)
	}()
	// The token goes whatever happened: it can sign with the operator
	// identity key. The main container also revokes it by accessor.
	return errors.Join(err, revokeToken(ctx, out, ob))
}

// readTokenFile returns the token in path. An unset path or a missing
// file is no token (check mode); an empty file is an error.
func readTokenFile(path string) (string, bool, error) {
	if path == "" {
		return "", false, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("reading the bootstrap token file: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", false, fmt.Errorf("the bootstrap token file %s is empty", path)
	}
	return tok, true, nil
}

// bootstrap is the run with a token: it checks every setting, creates the
// platform Transit keys, writes the trust ConfigMap, then the optional KV
// copy and, with EnvBusCAConfigMap, the bus CA ConfigMap.
func bootstrap(ctx context.Context, out io.Writer, kube *kubeClient, cmName string, cfg natskeys.Config, ob *openbao.Client) error {
	// Settings are checked before anything is created or written.
	kvCopy := os.Getenv(EnvKVCopy) == "true"
	mount := strings.Trim(os.Getenv(EnvKVMount), "/")
	if mount == "" {
		mount = DefaultKVMount
	}
	path := strings.Trim(os.Getenv(EnvKVPath), "/")
	if path == "" {
		path = DefaultKVPath
	}
	if kvCopy && (!kvPathMatcher.MatchString(mount) || !kvPathMatcher.MatchString(path)) {
		return fmt.Errorf("%w: KV copy target %q/%q is not a plain path", errUsage, mount, path)
	}
	fence := os.Getenv(EnvBusFenceUserPub)
	if fence != "" && !nkeys.IsValidPublicUserKey(fence) {
		return fmt.Errorf("%w: %s is not a user public key", errUsage, EnvBusFenceUserPub)
	}
	loader := os.Getenv(EnvBusLoaderUserPub)
	if loader != "" && !nkeys.IsValidPublicUserKey(loader) {
		return fmt.Errorf("%w: %s is not a user public key", errUsage, EnvBusLoaderUserPub)
	}
	if loader != "" && loader == fence {
		return fmt.Errorf("%w: %s and %s must be different keys", errUsage, EnvBusLoaderUserPub, EnvBusFenceUserPub)
	}
	operatorName := os.Getenv(EnvOperatorName)
	if operatorName == "" {
		operatorName = DefaultOperatorName
	}
	busCA := os.Getenv(EnvBusCAConfigMap)
	pkiMount := strings.Trim(os.Getenv(EnvBusCAPKIMount), "/")
	if busCA != "" {
		if !configMapNameMatcher.MatchString(busCA) {
			return fmt.Errorf("%w: %s=%q is not a valid ConfigMap name", errUsage, EnvBusCAConfigMap, busCA)
		}
		if busCA == cmName {
			return fmt.Errorf("%w: %s and %s must name different ConfigMaps", errUsage, EnvBusCAConfigMap, EnvTrustConfigMap)
		}
		if !kvPathMatcher.MatchString(pkiMount) {
			return fmt.Errorf("%w: %s=%q is not a plain mount path (required with %s)", errUsage, EnvBusCAPKIMount, pkiMount, EnvBusCAConfigMap)
		}
	}

	ks, err := natskeys.NewTransitKeyStore(cfg)
	if err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	defer ks.Close()
	for _, k := range platformKeys {
		kp, err := ks.EnsureKeyPair(ctx, k.name, k.prefix)
		if err != nil {
			return fmt.Errorf("transit key %s: %w", k.name, err)
		}
		pub, err := kp.PublicKey()
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "transit key %s: %s\n", k.name, pub)
	}

	in := pki.BootstrapInput{OperatorName: operatorName, BusFenceUserPub: fence, BusLoaderUserPub: loader}
	trust, written, err := writeTrust(ctx, kube, cmName, ks, in)
	if err != nil {
		return err
	}
	if written {
		fmt.Fprintf(out, "trust configmap %s/%s written\n", kube.namespace, cmName)
	} else {
		fmt.Fprintf(out, "trust configmap %s/%s is current; nothing written\n", kube.namespace, cmName)
	}

	if kvCopy {
		written, err := copyToKV(ctx, ob, mount, path, trust.Files())
		if err != nil {
			return fmt.Errorf("copying the trust to KV %s/data/%s: %w", mount, path, err)
		}
		if written {
			fmt.Fprintf(out, "trust copied to KV %s/data/%s\n", mount, path)
		}
	}

	if busCA != "" {
		caPEM, err := readBusCA(ctx, ob, pkiMount)
		if err != nil {
			return err
		}
		written, err := writeBusCA(ctx, kube, busCA, caPEM)
		if err != nil {
			return err
		}
		if written {
			fmt.Fprintf(out, "bus CA configmap %s/%s written from %s/cert/ca\n", kube.namespace, busCA, pkiMount)
		} else {
			fmt.Fprintf(out, "bus CA configmap %s/%s is current; nothing written\n", kube.namespace, busCA)
		}
	}
	return nil
}

// readBusCA returns the PEM certificate of the PKI mount's default
// issuer, <mount>/cert/ca: exactly the issuing_ca of a certificate the
// mount issues, for a root and for an intermediate issuer alike
// (TestBusCAIsIssuingCAOpenBao). The path is unauthenticated, so the
// handoff token's policy needs no grant for it. It must be one parsable
// CA certificate.
func readBusCA(ctx context.Context, ob *openbao.Client, mount string) (string, error) {
	secret, err := ob.Read(ctx, mount+"/cert/ca", nil)
	if err != nil {
		return "", fmt.Errorf("reading the bus CA from %s/cert/ca: %w", mount, err)
	}
	var d struct {
		Certificate string `json:"certificate"`
	}
	if err := openbao.DecodeData(secret, &d); err != nil {
		return "", fmt.Errorf("reading the bus CA from %s/cert/ca: %w", mount, err)
	}
	block, rest := pem.Decode([]byte(d.Certificate))
	if block == nil || block.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		return "", fmt.Errorf("%s/cert/ca is not one PEM certificate: does the mount have an issuer?", mount)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("%s/cert/ca: %w", mount, err)
	}
	if !cert.IsCA {
		return "", fmt.Errorf("%s/cert/ca is not a CA certificate", mount)
	}
	return d.Certificate, nil
}

// writeBusCA sets key BusCAKey of ConfigMap name to caPEM, creating it
// when absent and updating it when the PEM changed; other keys and the
// metadata are kept. It reports whether it wrote. A write that loses a
// race is retried from a fresh read.
func writeBusCA(ctx context.Context, kube *kubeClient, name, caPEM string) (bool, error) {
	for attempt := 0; ; attempt++ {
		cm, err := kube.getConfigMap(ctx, name)
		if err != nil {
			return false, err
		}
		switch {
		case cm == nil:
			err = kube.createConfigMap(ctx, &configMap{
				APIVersion: "v1",
				Kind:       "ConfigMap",
				Metadata:   map[string]any{"name": name, "namespace": kube.namespace},
				Data:       map[string]string{BusCAKey: caPEM},
			})
		case cm.Data[BusCAKey] == caPEM:
			return false, nil
		default:
			if cm.Data == nil {
				cm.Data = map[string]string{}
			}
			cm.Data[BusCAKey] = caPEM
			err = kube.updateConfigMap(ctx, cm)
		}
		if errors.Is(err, errConflict) && attempt < conflictRetries {
			continue
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}
}

// writeTrust reads the ConfigMap, bootstraps the trust over its data and
// writes the merged result (other keys are kept) when it differs. A
// write that loses a race is retried from a fresh read.
func writeTrust(ctx context.Context, kube *kubeClient, cmName string, ks natskeys.KeyStore, in pki.BootstrapInput) (*pki.NATSTrust, bool, error) {
	for attempt := 0; ; attempt++ {
		cm, err := kube.getConfigMap(ctx, cmName)
		if err != nil {
			return nil, false, err
		}
		var existing map[string]string
		if cm != nil {
			existing = cm.Data
		}
		in.Existing = bytesMap(existing)
		trust, err := pki.BootstrapNATSTrust(ctx, ks, in)
		if err != nil {
			return nil, false, err
		}
		data := maps.Clone(existing)
		if data == nil {
			data = map[string]string{}
		}
		for k, v := range trust.Files() {
			data[k] = string(v)
		}
		if cm != nil && maps.Equal(cm.Data, data) {
			return trust, false, nil
		}
		if cm == nil {
			err = kube.createConfigMap(ctx, &configMap{
				APIVersion: "v1",
				Kind:       "ConfigMap",
				Metadata:   map[string]any{"name": cmName, "namespace": kube.namespace},
				Data:       data,
			})
		} else {
			cm.Data = data
			err = kube.updateConfigMap(ctx, cm)
		}
		if errors.Is(err, errConflict) && attempt < conflictRetries {
			continue
		}
		if err != nil {
			return nil, false, err
		}
		return trust, true, nil
	}
}

// check is the run without a bootstrap token: the ConfigMap must exist
// and parse, and match Transit when an OpenBao identity is configured.
func check(ctx context.Context, out io.Writer, kube *kubeClient, cmName string) error {
	cm, err := kube.getConfigMap(ctx, cmName)
	if err != nil {
		return err
	}
	if cm == nil {
		return fmt.Errorf("no bootstrap token (%s) and the trust configmap %s/%s does not exist: run the bootstrap Job with a root token",
			EnvTokenFile, kube.namespace, cmName)
	}
	trust, err := pki.ParseNATSTrust(bytesMap(cm.Data))
	if err != nil {
		return fmt.Errorf("no bootstrap token (%s) and the trust configmap %s/%s is not usable: %w",
			EnvTokenFile, kube.namespace, cmName, err)
	}
	p := natskeys.EnvPrefixBoot
	method := os.Getenv(p + natskeys.EnvOpenBaoAuthMethod)
	if os.Getenv(p+natskeys.EnvOpenBaoAddr) == "" ||
		((method == "" || method == openbao.AuthMethodToken) && os.Getenv(p+natskeys.EnvOpenBaoToken) == "") {
		fmt.Fprintf(out, "trust configmap %s/%s is complete; no OpenBao identity, so not compared with Transit (farmer compares at start)\n",
			kube.namespace, cmName)
		return nil
	}
	cfg, err := natskeys.ConfigFromEnv(p, os.Getenv)
	if err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	ks, err := natskeys.NewTransitKeyStore(cfg)
	if err != nil {
		return fmt.Errorf("%w: %w", errUsage, err)
	}
	defer ks.Close()
	if err := trust.VerifyAgainst(ctx, ks); err != nil {
		return fmt.Errorf("trust configmap %s/%s: %w", kube.namespace, cmName, err)
	}
	fmt.Fprintf(out, "trust configmap %s/%s is complete and matches Transit\n", kube.namespace, cmName)
	return nil
}

// copyToKV writes files to KV v2 mount/data/path unless the current
// version already holds exactly them. It reports whether it wrote.
func copyToKV(ctx context.Context, ob *openbao.Client, mount, path string, files map[string][]byte) (bool, error) {
	want := map[string]string{}
	for k, v := range files {
		want[k] = string(v)
	}
	p := mount + "/data/" + path
	secret, err := ob.Read(ctx, p, nil)
	switch {
	case openbao.IsNotFound(err):
	case err != nil:
		return false, err
	default:
		var cur struct {
			Data map[string]string `json:"data"`
		}
		if err := openbao.DecodeData(secret, &cur); err == nil && maps.Equal(cur.Data, want) {
			return false, nil
		}
	}
	if _, err := ob.Put(ctx, p, map[string]any{"data": want}); err != nil {
		return false, err
	}
	return true, nil
}

// revokeToken revokes the bootstrap token (auth/token/revoke-self). It
// runs on a context of its own so a run that hit its deadline still
// revokes.
func revokeToken(ctx context.Context, out io.Writer, ob *openbao.Client) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if _, err := ob.Post(rctx, "auth/token/revoke-self", nil); err != nil {
		return fmt.Errorf("revoking the bootstrap token: %w", err)
	}
	fmt.Fprintln(out, "bootstrap token revoked")
	return nil
}

func bytesMap(m map[string]string) map[string][]byte {
	if m == nil {
		return nil
	}
	b := make(map[string][]byte, len(m))
	for k, v := range m {
		b[k] = []byte(v)
	}
	return b
}
