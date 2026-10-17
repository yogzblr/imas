// Package valkeyconn holds what farmer's and saasapi's Valkey clients need
// besides the node addresses: the password and the TLS settings (unit S5,
// docs/briefs/S5-valkey-hardening.md), and the startup check that Valkey
// does not evict keys.
//
// Each service reads the same four variables under its own prefix (IMAS
// for farmer, SAASAPI for saasapi):
//
//   - <P>_VALKEY_PASSWORD_FILE: path of the password of Valkey's "default"
//     ACL user, a file mounted from a Secret (the chart's imas-valkey-auth,
//     synced from OpenBao). Read once at startup, trailing newline trimmed;
//     set but unreadable or empty stops the process. Unset means no AUTH.
//     Rotation is a pod restart.
//   - <P>_VALKEY_TLS: "true" or "false" (default false).
//   - <P>_VALKEY_TLS_CA_FILE: the PEM CA bundle the server certificate must
//     chain to. Required with TLS; there is no fallback to the system roots.
//   - <P>_VALKEY_TLS_SERVER_NAME: the name to verify the certificate
//     against. Optional: by default the host of each address dialled.
//
// The password is never an environment variable: only its path is.
package valkeyconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	valkey "github.com/valkey-io/valkey-go"
)

// Username is the Valkey ACL user both services authenticate as.
const Username = "default"

// The variable suffixes; the full name is <prefix>_<suffix>.
const (
	SuffixPasswordFile  = "VALKEY_PASSWORD_FILE"
	SuffixTLS           = "VALKEY_TLS"
	SuffixTLSCAFile     = "VALKEY_TLS_CA_FILE"
	SuffixTLSServerName = "VALKEY_TLS_SERVER_NAME"
)

// Options are the resolved password and TLS settings. The zero value is
// no AUTH and no TLS. String and GoString never print the password.
type Options struct {
	// Password is the "default" user's password; empty means no AUTH.
	Password string
	// TLS is nil without TLS. With TLS it verifies the server against
	// the configured CA only, at TLS 1.2 or later.
	TLS *tls.Config
}

// String describes the options without the password.
func (o Options) String() string {
	auth := "no password"
	if o.Password != "" {
		auth = "password set"
	}
	tlsDesc := "no TLS"
	if o.TLS != nil {
		tlsDesc = "TLS"
		if o.TLS.ServerName != "" {
			tlsDesc += " (server name " + o.TLS.ServerName + ")"
		}
	}
	return auth + ", " + tlsDesc
}

// GoString is String, so %#v doesn't print the password either.
func (o Options) GoString() string { return o.String() }

// Load reads the <prefix>_VALKEY_* variables through getenv and the files
// they name. An error names the variable; it never contains the password.
func Load(prefix string, getenv func(string) string) (Options, error) {
	name := func(suffix string) string { return prefix + "_" + suffix }
	var o Options

	if path := strings.TrimSpace(getenv(name(SuffixPasswordFile))); path != "" {
		pw, err := readPassword(path)
		if err != nil {
			return Options{}, fmt.Errorf("%s=%q: %w", name(SuffixPasswordFile), path, err)
		}
		o.Password = pw
	}

	on := false
	if v := strings.TrimSpace(getenv(name(SuffixTLS))); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Options{}, fmt.Errorf("%s=%q: want true or false", name(SuffixTLS), v)
		}
		on = b
	}
	caFile := strings.TrimSpace(getenv(name(SuffixTLSCAFile)))
	serverName := strings.TrimSpace(getenv(name(SuffixTLSServerName)))
	if !on {
		// A CA or server name without TLS is a half-applied setting:
		// refuse it rather than connect in plaintext.
		for _, set := range []struct{ env, v string }{
			{name(SuffixTLSCAFile), caFile},
			{name(SuffixTLSServerName), serverName},
		} {
			if set.v != "" {
				return Options{}, fmt.Errorf("%s is set but %s is not true", set.env, name(SuffixTLS))
			}
		}
		return o, nil
	}
	if caFile == "" {
		return Options{}, fmt.Errorf("%s=true needs %s (a PEM CA bundle; the system roots are never used)", name(SuffixTLS), name(SuffixTLSCAFile))
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return Options{}, fmt.Errorf("%s=%q: %w", name(SuffixTLSCAFile), caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return Options{}, fmt.Errorf("%s=%q: no PEM certificate in it", name(SuffixTLSCAFile), caFile)
	}
	o.TLS = &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}
	return o, nil
}

// readPassword reads a password file: trailing CR/LF trimmed, and empty
// is an error.
func readPassword(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	pw := strings.TrimRight(string(b), "\r\n")
	if pw == "" {
		return "", errors.New("the password file is empty")
	}
	return pw, nil
}

// ClientOption is the valkey.ClientOption for addrs with these options.
// The caller sets anything else (DisableCache) on the result.
func (o Options) ClientOption(addrs []string) valkey.ClientOption {
	opt := valkey.ClientOption{InitAddress: addrs}
	if o.Password != "" {
		opt.Username = Username
		opt.Password = o.Password
	}
	if o.TLS != nil {
		opt.TLSConfig = o.TLS.Clone()
	}
	return opt
}

// EvictionCheckTimeout bounds CheckEviction's INFO call.
const EvictionCheckTimeout = 5 * time.Second

// CheckEviction reads INFO memory and logs one warning through warnf when
// Valkey may evict keys: maxmemory above 0 with a maxmemory_policy other
// than noeviction. The replay cache and the heartbeat keys are security
// state, and an evicted claim is a replay. Only a warning: a managed
// Valkey may not let the policy be changed. An INFO that fails or can't
// be parsed is logged too, and nothing else happens.
func CheckEviction(ctx context.Context, c valkey.Client, warnf func(string, ...any)) {
	ctx, cancel := context.WithTimeout(ctx, EvictionCheckTimeout)
	defer cancel()
	checkEviction(func() (string, error) {
		return c.Do(ctx, c.B().Info().Section("memory").Build()).ToString()
	}, warnf)
}

func checkEviction(info func() (string, error), warnf func(string, ...any)) {
	s, err := info()
	if err != nil {
		warnf("valkey: could not read INFO memory to check the eviction policy: %v", err)
		return
	}
	maxmemory, policy, err := parseMemoryInfo(s)
	if err != nil {
		warnf("valkey: could not check the eviction policy: %v", err)
		return
	}
	if maxmemory > 0 && policy != "noeviction" {
		warnf("valkey: maxmemory is %d with maxmemory-policy %s: Valkey may evict keys, and the replay cache and the heartbeat keys are security state (an evicted claim can be replayed); set maxmemory-policy noeviction", maxmemory, policy)
	}
}

// parseMemoryInfo returns maxmemory and maxmemory_policy from the text of
// INFO memory.
func parseMemoryInfo(s string) (int64, string, error) {
	var (
		maxmemory           int64
		policy              string
		haveMax, havePolicy bool
	)
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		switch k {
		case "maxmemory":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return 0, "", fmt.Errorf("INFO memory maxmemory %q is not a number", v)
			}
			maxmemory, haveMax = n, true
		case "maxmemory_policy":
			policy, havePolicy = v, true
		}
	}
	if !haveMax || !havePolicy {
		return 0, "", errors.New("INFO memory has no maxmemory or maxmemory_policy")
	}
	return maxmemory, policy, nil
}
