package natskeys

import (
	"fmt"
	"strconv"
	"time"

	"github.com/yogzblr/imas/internal/openbao"
)

// Environment prefixes of the two identities that use this package. The
// farmer and the SYS-JWT publish Job sign as IMAS_NATSSIGN_*; the
// bootstrap subcommand creates the platform keys as IMAS_NATSBOOT_*.
const (
	EnvPrefixSign = "IMAS_NATSSIGN_"
	EnvPrefixBoot = "IMAS_NATSBOOT_"
)

// Suffixes after the prefix, e.g. IMAS_NATSSIGN_OPENBAO_ADDR or
// IMAS_NATSSIGN_TIMEOUT.
const (
	EnvOpenBaoAddr          = "OPENBAO_ADDR"
	EnvOpenBaoCACert        = "OPENBAO_CACERT"
	EnvOpenBaoAuthMethod    = "OPENBAO_AUTH_METHOD"
	EnvOpenBaoToken         = "OPENBAO_TOKEN"
	EnvOpenBaoK8sRole       = "OPENBAO_K8S_ROLE"
	EnvOpenBaoK8sMount      = "OPENBAO_K8S_MOUNT"
	EnvOpenBaoK8sJWTPath    = "OPENBAO_K8S_JWT_PATH"
	EnvOpenBaoNamespace     = "OPENBAO_NAMESPACE"
	EnvOpenBaoAllowInsecure = "OPENBAO_ALLOW_INSECURE" // "true" accepts an http:// address
	EnvOpenBaoTransitMount  = "OPENBAO_TRANSIT_MOUNT"  // default "transit"
	EnvTimeout              = "TIMEOUT"                // default 15s
	EnvBatchMax             = "BATCH_MAX"              // default 64
	EnvWorkers              = "WORKERS"                // default 4
)

// Defaults for a Config's zero fields.
const (
	DefaultTransitMount = "transit"
	DefaultTimeout      = 15 * time.Second
	DefaultBatchMax     = 64
	DefaultWorkers      = 4
)

// ConfigFromEnv reads prefix's settings through getenv (os.Getenv in
// production). It returns an error wrapping ErrNotConfigured when
// <prefix>OPENBAO_ADDR is empty or a value does not parse. The OpenBao
// connection itself (token, CA, kubernetes auth) is read again from the
// process environment by internal/openbao when the store is built, so
// getenv must agree with it.
func ConfigFromEnv(prefix string, getenv func(string) string) (Config, error) {
	if getenv(prefix+EnvOpenBaoAddr) == "" {
		return Config{}, fmt.Errorf("%w: %s%s is required", ErrNotConfigured, prefix, EnvOpenBaoAddr)
	}
	cfg := Config{
		OpenBao: openbao.Env{
			Addr:       prefix + EnvOpenBaoAddr,
			CACert:     prefix + EnvOpenBaoCACert,
			AuthMethod: prefix + EnvOpenBaoAuthMethod,
			Token:      prefix + EnvOpenBaoToken,
			K8sRole:    prefix + EnvOpenBaoK8sRole,
			K8sMount:   prefix + EnvOpenBaoK8sMount,
			K8sJWTPath: prefix + EnvOpenBaoK8sJWTPath,
			Namespace:  prefix + EnvOpenBaoNamespace,

			AllowInsecure: prefix + EnvOpenBaoAllowInsecure,
		},
		TransitMount: getenv(prefix + EnvOpenBaoTransitMount),
	}
	if v := getenv(prefix + EnvTimeout); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("%w: %s%s=%q is not a positive duration", ErrNotConfigured, prefix, EnvTimeout, v)
		}
		cfg.Timeout = d
	}
	var err error
	if cfg.BatchMax, err = positiveInt(getenv, prefix+EnvBatchMax); err != nil {
		return Config{}, err
	}
	if cfg.Workers, err = positiveInt(getenv, prefix+EnvWorkers); err != nil {
		return Config{}, err
	}
	return cfg.withDefaults(), nil
}

// positiveInt reads name as an integer of at least 1; unset is 0 (the
// default applies).
func positiveInt(getenv func(string) string, name string) (int, error) {
	v := getenv(name)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%w: %s=%q is not a positive integer", ErrNotConfigured, name, v)
	}
	return n, nil
}
