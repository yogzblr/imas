package pki

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"strconv"

	log "github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/internal/config"

	jwt "github.com/nats-io/jwt/v2"
	nats_server "github.com/nats-io/nats-server/v2/server"
)

var (
	NatsServer *nats_server.Server
	NatsOpts   *nats_server.Options
	cert       tls.Certificate
	certPool   *x509.CertPool
)

// ConfigureNats builds the NATS server options for a bus node that shares
// this process, and its FarmerPKI directory, with core: the in-process
// core-plus-bus setup the package's tests use. Auth is decentralized JWT
// (see docs/design/imas-nats-jwt-auth-design.md): the Operator is the
// trust anchor, the SYSTEM account is used only to receive claims-update
// pushes (see resolver.go), and a "full" resolver (every node holds every
// Account JWT, appropriate at the near-term tenant count) is seeded with
// the SYSTEM and tenant Account JWTs core holds on disk, so the server can
// validate connections from the moment it starts.
//
// The DMZ bus (cmd/farmerbus) uses ConfigureBusNats instead (busauth.go),
// which seeds no claims of its own beyond a SYS bootstrap that can't
// outrank anything core signs.
func ConfigureNats() nats_server.Options {
	NatsConfig := baseNatsOptions()
	seedResolverFromCore(&NatsConfig)
	return NatsConfig
}

// baseNatsOptions builds the listeners and TLS for a bus node: the TCP
// client port and, when configured, the websocket port, both TLS only.
// It sets no auth; the callers add the operator, SYSTEM account and
// resolver.
func baseNatsOptions() nats_server.Options {
	var NatsConfig nats_server.Options
	FarmerInterface := config.FarmerInterface
	FBusPort := config.FarmerBusPort
	FarmerBusPort, err := strconv.Atoi(FBusPort)
	if err != nil {
		log.Panic(err)
	}
	RootCA := config.RootCA
	CertFile := config.CertFile
	KeyFile := config.KeyFile
	NatsConfig = nats_server.Options{
		Host:                  FarmerInterface,
		Port:                  FarmerBusPort,
		NoSigs:                true,
		MaxControlLine:        4096,
		DisableShortFirstPing: true,
		Trace:                 true,
		Debug:                 true,
		TLS:                   true,
		AllowNonTLS:           false,
		LogFile:               "nats.log",
		AuthTimeout:           10,
	}
	// 0 leaves nats-server's default (65,536). A negative MaxConn would
	// refuse every client, so only a positive value is passed through;
	// config.LoadConfig already turns a negative one into 0.
	if config.BusMaxConnections > 0 {
		NatsConfig.MaxConn = config.BusMaxConnections
	}
	certPool = x509.NewCertPool()
	rootPEM, err := os.ReadFile(RootCA)
	if err != nil || rootPEM == nil {
		log.Panicf("nats: error loading or parsing rootCA file: %v", err)
	}
	ok := certPool.AppendCertsFromPEM(rootPEM)
	if !ok {
		log.Errorf("nats: failed to parse root certificate from %v", RootCA)
	}
	cert, err = tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		log.Panic(err)
	}
	tlsConfig := tls.Config{
		ServerName:   FarmerInterface,
		RootCAs:      certPool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	NatsConfig.TLSConfig = &tlsConfig

	// Websocket listener: what Envoy's jwt_authn-gated wss:// route
	// (docs/design/imas-envoy-enrollment-design.md) terminates onto.
	// Reuses the same server certificate as the plain TCP listener above.
	// Auth here is still the ordinary decentralized JWT/NKey CONNECT-time
	// check (AccountResolver, set below) — Envoy's JWT validation happens
	// earlier, in front of this listener, not instead of it; see the
	// design doc's "two gates, checking different things, not redundant
	// with each other."
	//
	// FarmerWSPort defaults to "5407" via config.LoadConfig, but is left
	// unset by several existing tests that build config values directly
	// rather than loading them — treat that as "no websocket listener"
	// rather than failing the whole server start.
	if config.FarmerWSPort != "" {
		wsPort, err := strconv.Atoi(config.FarmerWSPort)
		if err != nil {
			log.Panic(err)
		}
		NatsConfig.Websocket = nats_server.WebsocketOpts{
			Host: FarmerInterface,
			Port: wsPort,
			TLSConfig: &tls.Config{
				ServerName:   FarmerInterface,
				RootCAs:      certPool,
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
			AuthTimeout: 10,
		}
	}

	return NatsConfig
}

// seedResolverFromCore adds ConfigureNats's auth: the operator, SYSTEM
// account and a full resolver seeded from core's material. The operator
// JWT and SYS account come from the trust directory (through
// ensureNatsAuth, which also gives the legacy tenant's Account); every
// provisioned tenant's Account JWT is read from the file core persisted,
// without touching that tenant's Transit keys, so seeding never creates
// or needs them. A missing or unusable tenant Account JWT is skipped;
// core's next push supplies it.
//
// The resolver's directory is its own, made by this call and removed when
// the server closes the resolver (newTempDirResolver): ConfigureNats
// serves only the in-process test bus, and nothing reads that directory
// again.
func seedResolverFromCore(NatsConfig *nats_server.Options) {
	mat, err := ensureNatsAuth()
	if err != nil {
		log.Panicf("nats: failed to bootstrap decentralized JWT auth material: %v", err)
	}
	seedResolverWith(NatsConfig, mat)
}

// seedResolverWith is seedResolverFromCore with core's material given.
func seedResolverWith(NatsConfig *nats_server.Options, mat *natsAuthMaterial) {
	opClaims, err := jwt.DecodeOperatorClaims(mat.operatorJWT)
	if err != nil {
		log.Panicf("nats: failed to decode operator JWT: %v", err)
	}
	NatsConfig.TrustedOperators = []*jwt.OperatorClaims{opClaims}
	NatsConfig.SystemAccount = mat.sysAccountPub

	resolver, err := newTempDirResolver()
	if err != nil {
		log.Panicf("nats: failed to create the account resolver: %v", err)
	}
	// Until the options hold it (the server's Shutdown closes it then), a
	// panic below must not leave its directory behind.
	handedOver := false
	defer func() {
		if !handedOver {
			resolver.Close()
		}
	}()
	if err := resolver.Store(mat.sysAccountPub, mat.sysAccountJWT); err != nil {
		log.Panicf("nats: failed to seed the SYS account into the resolver: %v", err)
	}
	if err := resolver.Store(mat.tenantPub, mat.tenantJWT); err != nil {
		log.Panicf("nats: failed to seed the tenant account into the resolver: %v", err)
	}
	operatorSigningPub, err := mat.operatorSigningKP.PublicKey()
	if err != nil {
		log.Panicf("nats: operator signing key: %v", err)
	}

	// Seed every additionally-provisioned tenant's Account too (workstream
	// E, FLAG FOR SECURITY REVIEW: tenant isolation correctness) — the
	// legacy single-tenant seam above only ever knows about the one Account
	// named by config.FarmerOrganization; ProvisionTenant (tenant.go) is
	// what actually makes multiple, dynamically-created tenant Accounts
	// exist, and every one of them needs to be in the resolver from the
	// moment this bus node starts, not just the tenant that happens to be
	// "current" for this process. This is a filesystem scan
	// (tenantIDsProvisionedOnDisk), not a pki_tenants/PXC query. A failure
	// loading one tenant's JWT is logged and skipped rather than panicking
	// the whole server — a bad on-disk file for one tenant shouldn't take
	// down every other tenant's bus access.
	ids, err := tenantIDsProvisionedOnDisk()
	if err != nil {
		log.Errorf("nats: failed to list provisioned tenants for resolver seeding: %v", err)
	}
	for _, id := range ids {
		b, err := os.ReadFile(tenantAccountJWTPath(id))
		if err != nil {
			log.Errorf("nats: failed to read tenant %q's Account JWT, skipping resolver seed: %v", id, err)
			continue
		}
		ac, err := jwt.DecodeAccountClaims(string(b))
		if err != nil || ac.Issuer != operatorSigningPub {
			log.Errorf("nats: tenant %q's Account JWT is invalid or not issued by the operator signing key, skipping resolver seed: %v", id, err)
			continue
		}
		if err := resolver.Store(ac.Subject, string(b)); err != nil {
			log.Errorf("nats: failed to seed tenant %q's account into the resolver: %v", id, err)
		}
	}
	NatsConfig.AccountResolver = resolver
	handedOver = true
}

// tempDirResolver is a full account resolver over a directory of its
// own, which Close (called by the server's Shutdown) removes.
type tempDirResolver struct {
	*nats_server.DirAccResolver
	dir string
}

// newTempDirResolver makes a fresh directory in the process's temp
// directory and a full resolver over it.
func newTempDirResolver() (*tempDirResolver, error) {
	dir, err := os.MkdirTemp("", "imas-bus-resolver-")
	if err != nil {
		return nil, err
	}
	r, err := nats_server.NewDirAccResolver(dir, 0, 0, nats_server.HardDelete)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &tempDirResolver{DirAccResolver: r, dir: dir}, nil
}

// Close closes the resolver and removes its directory.
func (r *tempDirResolver) Close() {
	r.DirAccResolver.Close()
	if err := os.RemoveAll(r.dir); err != nil {
		log.Warnf("nats: removing the account resolver directory %s: %v", r.dir, err)
	}
}

func SetNATSServer(s *nats_server.Server) {
	NatsServer = s
}

// ReloadNKeys recomputes the tenant Account's User JWTs and revocation list
// from the current accept/deny/reject/unaccept sprout state (see
// syncNatsAuth in jwtusers.go), and, if that changed the Account JWT,
// pushes the update to the resolver (see resolver.go).
//
// This replaces the old behavior of rebuilding an NkeyUser allow-list and
// calling NatsServer.ReloadOptions() in-process; the name is kept because
// pki.go's Accept/Deny/Reject/Unaccept/Delete all call it via defer, and
// cmd/farmer/main.go calls it directly on SIGHUP.
//
// The push (pushAccountUpdate -> connectSystemAccount) dials
// config.FarmerBusURL over the network as the SYS account; it does not
// depend on this process holding a local NatsServer handle, so the push is
// always attempted when changed is true, regardless of whether this
// process itself embeds the bus. That must stay true once farmer's bus and
// core processes are split into separate binaries (workstream C): the core
// process, where Accept/Deny/API calls happen, will never have a local
// NatsServer, but it still needs its pushes to reach the bus.
func ReloadNKeys() error {
	mat, err := ensureNatsAuth()
	if err != nil {
		log.Errorf("failed to bootstrap NATS decentralized-auth material: %v", err)
		return err
	}
	changed, err := syncNatsAuth(mat)
	if err != nil {
		log.Errorf("failed to sync the tenant Account JWT: %v", err)
		return err
	}
	if !changed {
		return nil
	}
	if err := pushAccountUpdate(mat, mat.tenantJWT); err != nil {
		log.Errorf("failed to push the updated Account JWT to the bus resolver: %v", err)
		return err
	}
	log.Tracef("Pushed updated tenant Account JWT to the bus resolver.")
	return nil
}
