// Package certs issues and rotates farmer/sprout TLS material from
// OpenBao's PKI secrets engine, writing the results to the same
// config.CertFile/KeyFile/RootCA paths that internal/pki/nats.go and the
// API server already consume.
//
// The client is internal/openbao (the official OpenBao Go client), which
// owns auth, TLS and error decoding for every server-side OpenBao
// identity. Authentication is pluggable via IMAS_CERTS_OPENBAO_AUTH_METHOD:
// a static bearer token (the default, IMAS_CERTS_OPENBAO_TOKEN) or OpenBao's
// native "kubernetes" auth method, which logs in with the pod's own service
// account JWT and needs no long-lived secret placed in the environment.
package certs

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yogzblr/imas/internal/config"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/openbao"
)

// Environment variables configuring the OpenBao PKI client. Addr and Role
// are always required; which of the rest are required depends on
// AuthMethod (see newClientFromEnv).
const (
	EnvOpenBaoAddr       = "IMAS_CERTS_OPENBAO_ADDR"
	EnvOpenBaoPKIMount   = "IMAS_CERTS_OPENBAO_PKI_MOUNT" // default "pki"
	EnvOpenBaoRole       = "IMAS_CERTS_OPENBAO_ROLE"
	EnvOpenBaoCACert     = "IMAS_CERTS_OPENBAO_CACERT"      // optional, verify OpenBao's own TLS
	EnvOpenBaoAuthMethod = "IMAS_CERTS_OPENBAO_AUTH_METHOD" // "token" (default) or "kubernetes"

	// EnvOpenBaoToken is the bearer token used when AuthMethod is "token"
	// (the default, for backward compatibility with existing deployments).
	EnvOpenBaoToken = "IMAS_CERTS_OPENBAO_TOKEN"

	// EnvOpenBaoK8sRole, EnvOpenBaoK8sMount and EnvOpenBaoK8sJWTPath
	// configure OpenBao's kubernetes auth method, used when AuthMethod is
	// "kubernetes". EnvOpenBaoK8sRole is required in that case; the other
	// two have defaults matching a standard in-cluster deployment.
	EnvOpenBaoK8sRole    = "IMAS_CERTS_OPENBAO_K8S_ROLE"
	EnvOpenBaoK8sMount   = "IMAS_CERTS_OPENBAO_K8S_MOUNT"    // default "kubernetes"
	EnvOpenBaoK8sJWTPath = "IMAS_CERTS_OPENBAO_K8S_JWT_PATH" // default openbao.DefaultK8sJWTPath

	// EnvOpenBaoNamespace optionally sets the X-Vault-Namespace header.
	EnvOpenBaoNamespace = "IMAS_CERTS_OPENBAO_NAMESPACE"
)

// Recognized values for IMAS_CERTS_OPENBAO_AUTH_METHOD.
const (
	AuthMethodToken      = openbao.AuthMethodToken
	AuthMethodKubernetes = openbao.AuthMethodKubernetes
)

var openBaoEnv = openbao.Env{
	Addr:       EnvOpenBaoAddr,
	CACert:     EnvOpenBaoCACert,
	AuthMethod: EnvOpenBaoAuthMethod,
	Token:      EnvOpenBaoToken,
	K8sRole:    EnvOpenBaoK8sRole,
	K8sMount:   EnvOpenBaoK8sMount,
	K8sJWTPath: EnvOpenBaoK8sJWTPath,
	Namespace:  EnvOpenBaoNamespace,
}

var (
	ErrNotConfigured = errors.New("openbao PKI client not configured")
	ErrIssueFailed   = errors.New("openbao certificate issuance failed")
	ErrRenewFailed   = errors.New("openbao lease renewal failed")
	ErrCAFetchFailed = errors.New("openbao CA certificate fetch failed")

	// ErrK8sJWTUnavailable means this process's own service account JWT
	// couldn't be read -- a local problem (bad EnvOpenBaoK8sJWTPath, or
	// not actually running in a pod with a projected SA token), and login
	// was never attempted.
	ErrK8sJWTUnavailable = errors.New("openbao kubernetes auth: could not read service account token")
	// ErrK8sAuthFailed means OpenBao itself rejected the kubernetes auth
	// login attempt: an unknown role, a TokenReview failure because
	// OpenBao's configured kubernetes_host is unreachable, an expired JWT,
	// etc. The wrapped message preserves OpenBao's own error text, which
	// is normally enough to tell these cases apart.
	ErrK8sAuthFailed = errors.New("openbao kubernetes auth login failed")
)

// obClient is a client for the subset of OpenBao's HTTP API this
// package needs: the PKI secrets engine's issue and ca endpoints, and
// sys/leases/renew.
type obClient struct {
	ob    *openbao.Client
	mount string // PKI secrets engine mount
	role  string // PKI role
}

// newClientFromEnv builds an obClient from the Env* variables above. It is
// called fresh on every operation (rather than cached at package init)
// so that changes to the environment -- as tests make routinely, pointing
// at a local OpenBao dev server -- take effect immediately. Callers
// Close it when the operation is done.
func newClientFromEnv() (*obClient, error) {
	addr := os.Getenv(EnvOpenBaoAddr)
	role := os.Getenv(EnvOpenBaoRole)
	if addr == "" || role == "" {
		return nil, fmt.Errorf("%w: %s and %s are required", ErrNotConfigured, EnvOpenBaoAddr, EnvOpenBaoRole)
	}
	ob, err := openbao.NewFromEnv(openBaoEnv, openbao.Errors{
		NotConfigured:     ErrNotConfigured,
		K8sJWTUnavailable: ErrK8sJWTUnavailable,
		K8sAuthFailed:     ErrK8sAuthFailed,
	})
	if err != nil {
		return nil, err
	}
	mount := os.Getenv(EnvOpenBaoPKIMount)
	if mount == "" {
		mount = "pki"
	}
	return &obClient{ob: ob, mount: mount, role: role}, nil
}

// Close releases the client's idle connections.
func (c *obClient) Close() { c.ob.Close() }

// requestErr wraps a failed request in sentinel, except a kubernetes
// login failure, which is returned as is (ErrK8sAuthFailed or
// ErrK8sJWTUnavailable alone, as before the shared client).
func requestErr(sentinel, err error) error {
	if errors.Is(err, ErrK8sAuthFailed) || errors.Is(err, ErrK8sJWTUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %w", sentinel, err)
}

type issueRequest struct {
	CommonName string `json:"common_name"`
	AltNames   string `json:"alt_names,omitempty"`
	IPSans     string `json:"ip_sans,omitempty"`
	TTL        string `json:"ttl,omitempty"`
	// ExcludeCNFromSans is always true (see issueCert): without it, OpenBao
	// additionally adds CommonName itself as a DNS SAN entry, even when it
	// is an IP-shaped string that's already been supplied via IPSans,
	// producing a spurious extra SAN.
	ExcludeCNFromSans bool `json:"exclude_cn_from_sans"`
}

type issueData struct {
	Certificate string `json:"certificate"`
	IssuingCA   string `json:"issuing_ca"`
	PrivateKey  string `json:"private_key"`
}

type issueResponse struct {
	LeaseID       string    `json:"lease_id"`
	LeaseDuration int       `json:"lease_duration"`
	Renewable     bool      `json:"renewable"`
	Data          issueData `json:"data"`
}

// issueCert requests a new leaf certificate for hosts from the configured
// PKI role. IPs and DNS names in hosts are split into ip_sans/alt_names;
// the first host becomes the certificate's CommonName, matching how
// config.CertHosts was previously used to build SANs directly.
func (c *obClient) issueCert(ctx context.Context, hosts []string, ttl time.Duration) (*issueResponse, error) {
	var dnsNames, ips []string
	for _, h := range hosts {
		if net.ParseIP(h) != nil {
			ips = append(ips, h)
		} else {
			dnsNames = append(dnsNames, h)
		}
	}
	cn := "imas"
	switch {
	case len(dnsNames) > 0:
		cn = dnsNames[0]
	case len(ips) > 0:
		cn = ips[0]
	}
	reqBody := issueRequest{
		CommonName:        cn,
		AltNames:          strings.Join(dnsNames, ","),
		IPSans:            strings.Join(ips, ","),
		ExcludeCNFromSans: true,
	}
	if ttl > 0 {
		reqBody.TTL = ttl.String()
	}
	secret, err := c.ob.Post(ctx, c.mount+"/issue/"+c.role, reqBody)
	if err != nil {
		return nil, requestErr(ErrIssueFailed, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("%w: empty response", ErrIssueFailed)
	}
	ir := &issueResponse{LeaseID: secret.LeaseID, LeaseDuration: secret.LeaseDuration, Renewable: secret.Renewable}
	if err := openbao.DecodeData(secret, &ir.Data); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIssueFailed, err)
	}
	if ir.Data.Certificate == "" || ir.Data.PrivateKey == "" {
		return nil, fmt.Errorf("%w: response had no certificate/private_key", ErrIssueFailed)
	}
	return ir, nil
}

// fetchCACertPEM fetches the PKI mount's current CA certificate. Unlike
// the issue endpoint, ca/pem returns the raw PEM bytes directly rather
// than a JSON envelope.
func (c *obClient) fetchCACertPEM(ctx context.Context) ([]byte, error) {
	data, err := c.ob.ReadRaw(ctx, c.mount+"/ca/pem")
	if err != nil {
		return nil, requestErr(ErrCAFetchFailed, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty CA certificate returned", ErrCAFetchFailed)
	}
	return data, nil
}

type renewRequest struct {
	LeaseID   string `json:"lease_id"`
	Increment int    `json:"increment,omitempty"`
}

type renewResponse struct {
	LeaseID       string
	LeaseDuration int
	Renewable     bool
}

// renewLease asks OpenBao to renew leaseID by increment.
//
// Note for reviewers: OpenBao's (and upstream Vault's) PKI secrets engine
// issues certificates with a fixed NotAfter baked into the certificate at
// issuance time -- renewing the lease does not and cannot extend that
// certificate's actual validity, and a real OpenBao server responds to
// this call with "lease is not renewable" for PKI issue leases (verified
// against a local OpenBao dev server; see certs_test.go). This
// method still asks OpenBao rather than deciding locally, per this
// workstream's brief to drive rotation off OpenBao's lease state instead
// of a self-managed timer: RotateTLSCerts calls this first and only falls
// back to reissuing a fresh certificate when OpenBao reports the lease
// can't be (or wasn't) extended far enough past the rotation threshold.
func (c *obClient) renewLease(ctx context.Context, leaseID string, increment time.Duration) (*renewResponse, error) {
	reqBody := renewRequest{LeaseID: leaseID}
	if increment > 0 {
		reqBody.Increment = int(increment.Seconds())
	}
	secret, err := c.ob.Put(ctx, "sys/leases/renew", reqBody)
	if err != nil {
		return nil, requestErr(ErrRenewFailed, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("%w: empty response", ErrRenewFailed)
	}
	return &renewResponse{LeaseID: secret.LeaseID, LeaseDuration: secret.LeaseDuration, Renewable: secret.Renewable}, nil
}

// leaseID tracks the most recently issued certificate's OpenBao lease for
// this process, so RotateTLSCerts can attempt a lease renewal before
// falling back to reissuing. It is intentionally in-memory only: after a
// process restart there is no lease to renew, and RotateTLSCerts falls
// back to reading the certificate's own NotAfter in that case.
var (
	leaseMu        sync.Mutex
	currentLeaseID string
)

func rememberLease(id string) {
	leaseMu.Lock()
	currentLeaseID = id
	leaseMu.Unlock()
}

func currentLease() string {
	leaseMu.Lock()
	defer leaseMu.Unlock()
	return currentLeaseID
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// genCACert fetches the PKI mount's CA certificate from OpenBao and writes
// it to config.RootCA. OpenBao custodies the CA private key itself -- it
// never leaves OpenBao and never touches this process -- so, unlike the
// old self-signed implementation, there is no CA key file to generate or
// manage here; config.RootCAPriv is no longer used by this package.
func genCACert() error {
	client, err := newClientFromEnv()
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	caPEM, err := client.fetchCACertPEM(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch CA certificate: %w", err)
	}
	if err := writeFile(config.RootCA, caPEM, 0o644); err != nil {
		return fmt.Errorf("failed to write CA cert file %s: %w", config.RootCA, err)
	}
	log.Debugf("wrote %s", config.RootCA)
	return nil
}

// issueAndWrite fetches the current CA certificate and issues a fresh leaf
// certificate from OpenBao's PKI secrets engine, writing all three
// artifacts (RootCA, CertFile, KeyFile) to disk.
func issueAndWrite() error {
	if err := genCACert(); err != nil {
		return err
	}
	client, err := newClientFromEnv()
	if err != nil {
		return err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ir, err := client.issueCert(ctx, config.CertHosts, config.CertificateValidTime)
	if err != nil {
		return fmt.Errorf("failed to issue TLS certificate: %w", err)
	}
	if err := writeFile(config.CertFile, []byte(ir.Data.Certificate), 0o644); err != nil {
		return fmt.Errorf("failed to write cert file %s: %w", config.CertFile, err)
	}
	log.Debug("wrote cert.pem")
	if err := writeFile(config.KeyFile, []byte(ir.Data.PrivateKey), 0o600); err != nil {
		return fmt.Errorf("failed to write key file %s: %w", config.KeyFile, err)
	}
	log.Debug("wrote key.pem")

	rememberLease(ir.LeaseID)
	return nil
}

// GenCert ensures a TLS server certificate and private key exist at
// config.CertFile/config.KeyFile, issuing them from OpenBao's PKI secrets
// engine if they don't. If a cert and key already exist, it does nothing
// -- callers wanting a fresh certificate should use RotateTLSCerts.
func GenCert() error {
	_, err := os.Stat(config.CertFile)
	if !os.IsNotExist(err) {
		_, errKey := os.Stat(config.KeyFile)
		if !os.IsNotExist(errKey) {
			log.Trace("Found a TLS keypair, not generating a new one...")
			return nil
		}
	}
	return issueAndWrite()
}

// RotateTLSCerts checks whether the current TLS leaf certificate needs
// rotating and, if so, replaces it with a freshly issued one from
// OpenBao.
//
// Whether rotation is due at all is still decided from the certificate's
// own NotAfter vs. threshold -- that's a local, free check, and there is
// no reason to call out to OpenBao at all for a certificate that is
// nowhere near expiry. Once rotation is due, though, this is where the
// old self-managed-timer implementation simply regenerated a new
// certificate locally; here, if this process holds an OpenBao lease for
// the current certificate, it asks OpenBao to renew that lease first, and
// only reissues when OpenBao reports the lease can't be extended past
// threshold (which, for the PKI secrets engine, is the normal case --
// see the comment on (*obClient).renewLease). When no lease is tracked
// (e.g. right after a process restart), it reissues directly, since there
// is no lease handle to ask OpenBao about.
//
// Returns true if the certificate was rotated.
func RotateTLSCerts(threshold time.Duration) (bool, error) {
	certBytes, err := os.ReadFile(config.CertFile)
	if err != nil {
		if os.IsNotExist(err) {
			if err := GenCert(); err != nil {
				return false, fmt.Errorf("failed to generate cert: %w", err)
			}
			return true, nil
		}
		return false, fmt.Errorf("failed to read cert file: %w", err)
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		log.Warn("TLS certificate PEM is corrupt, regenerating")
		return forceRegenCert()
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Warnf("Failed to parse TLS certificate: %v, regenerating", err)
		return forceRegenCert()
	}

	remaining := time.Until(cert.NotAfter)
	if remaining > threshold {
		log.Tracef("TLS certificate valid for %s, rotation threshold is %s — no rotation needed",
			remaining.Round(time.Minute), threshold.Round(time.Minute))
		return false, nil
	}
	log.Infof("TLS certificate expires in %s (threshold %s), rotation due",
		remaining.Round(time.Minute), threshold.Round(time.Minute))

	leaseID := currentLease()
	if leaseID == "" {
		log.Debug("no OpenBao lease tracked for the current certificate, reissuing")
		return forceRegenCert()
	}

	client, err := newClientFromEnv()
	if err != nil {
		return false, fmt.Errorf("failed to build OpenBao client for lease renewal: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	rr, renewErr := client.renewLease(ctx, leaseID, config.CertificateValidTime)
	cancel()
	client.Close()
	if renewErr != nil {
		log.Infof("openbao lease %s could not be renewed (%v), reissuing certificate", leaseID, renewErr)
		return forceRegenCert()
	}
	renewedRemaining := time.Duration(rr.LeaseDuration) * time.Second
	if renewedRemaining > threshold {
		rememberLease(rr.LeaseID)
		log.Tracef("openbao renewed lease %s, %s remaining (threshold %s) — no rotation needed",
			rr.LeaseID, renewedRemaining.Round(time.Minute), threshold.Round(time.Minute))
		return false, nil
	}
	log.Infof("openbao lease %s renewed but only %s remains (threshold %s), reissuing certificate",
		rr.LeaseID, renewedRemaining.Round(time.Minute), threshold.Round(time.Minute))
	return forceRegenCert()
}

// forceRegenCert removes the existing server cert and key, then issues a
// fresh pair from OpenBao's PKI secrets engine.
func forceRegenCert() (bool, error) {
	if err := os.Remove(config.CertFile); err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("failed to remove old cert: %w", err)
	}
	if err := os.Remove(config.KeyFile); err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("failed to remove old key: %w", err)
	}
	if err := issueAndWrite(); err != nil {
		return false, fmt.Errorf("failed to reissue TLS certificate: %w", err)
	}
	return true, nil
}
