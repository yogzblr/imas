// Command stubfarmer stands in for farmer in the Ansible roles' Molecule
// tests (ansible/molecule/): just enough of it for a packaged imas-sprout
// to enroll with a join token and connect to the bus, without the PXC,
// OpenBao and Valkey a real farmer needs.
//
// It serves, over TLS from a CA it generates at startup (written to
// -state-dir/ca.pem, so the playbook can pre-provision it as the sprout's
// root CA, the DMZ way):
//
//   - POST /v1/enroll: checks proof of possession the way farmer does
//     (pki.EnrollSigningPayload, signed by nkey_pub), then the join token.
//     A request from an already-enrolled nkey_pub is answered from the
//     replay path without spending a use, like farmer's step 1. Failures
//     are the generic 403 enrollment_failed.
//   - POST /v1/refresh: a fresh gateway JWT for an enrolled nkey_pub.
//   - GET /_stub/state: what the tests assert on (join token redemptions,
//     enrollments, and the NKeys connected to the bus).
//   - the fleet update endpoints in fleet.go, for testing/selfupdate-e2e.
//
// With -static-dir, it also serves that directory over plain HTTP on
// -static-addr: the tests' signed apt and rpm repositories.
//
// and an embedded nats-server in operator mode that accepts the User JWTs
// it mints. None of this is a security boundary: it exists only for tests.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"
	natsjwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/pki"
)

// maxSkew matches farmer's EnrollSigMaxSkew.
const maxSkew = 5 * time.Minute

// stubTenantID is the one tenant every sprout enrolls into. The gateway
// JWT carries it, as internal/gatewayjwt's does.
const stubTenantID = "t_molecule"

type enrollRequest struct {
	JoinToken string `json:"join_token"`
	NKeyPub   string `json:"nkey_pub"`
	Hostname  string `json:"hostname"`
	SproutPub string `json:"sprout_pub"`
	Timestamp int64  `json:"timestamp"`
	NKeySig   string `json:"nkey_sig"`
}

type refreshRequest struct {
	NKeyPub   string `json:"nkey_pub"`
	Timestamp int64  `json:"timestamp"`
	NKeySig   string `json:"nkey_sig"`
}

// State is GET /_stub/state's body.
type State struct {
	// Redemptions counts join token uses: first-time enrollments only.
	Redemptions int `json:"redemptions"`
	// EnrollRequests counts every POST /v1/enroll, replays and failures
	// included.
	EnrollRequests int `json:"enroll_requests"`
	// Sprouts maps each enrolled NKey to its sprout ID.
	Sprouts map[string]string `json:"sprouts"`
	// Connected lists the NKeys with a client connection to the bus.
	Connected []string `json:"connected"`
}

type farmer struct {
	joinToken string
	maxUses   int
	natsURLs  []string

	account     nkeys.KeyPair
	gatewayKey  ed25519.PrivateKey
	tenantBoxPK string
	// tenantBoxPriv is the tenant X25519 key cook dispatches are sealed
	// under (fleet.go); tenantBoxPK is its public half.
	tenantBoxPriv *[32]byte
	fleet         *fleetState
	// nc is the stub's own bus connection, for sealed cook dispatch.
	nc        *nats.Conn
	now       func() time.Time
	connected func() []string

	mu             sync.Mutex
	redemptions    int
	enrollRequests int
	sprouts        map[string]string    // nkey_pub -> sprout ID
	sproutBox      map[string]*[32]byte // sprout ID -> its X25519 box public key
	seenSigs       map[string]bool
}

func newFarmer(joinToken string, maxUses int, natsURLs []string) (*farmer, error) {
	account, err := nkeys.CreateAccount()
	if err != nil {
		return nil, err
	}
	_, gatewayKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	_, fleetPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	fleet, err := newFleetState(fleetPriv)
	if err != nil {
		return nil, err
	}
	boxPub, boxPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &farmer{
		tenantBoxPriv: boxPriv,
		fleet:         fleet,
		sproutBox:     map[string]*[32]byte{},
		joinToken:     joinToken,
		maxUses:       maxUses,
		natsURLs:      natsURLs,
		account:       account,
		gatewayKey:    gatewayKey,
		tenantBoxPK:   base64.StdEncoding.EncodeToString(boxPub[:]),
		now:           time.Now,
		connected:     func() []string { return nil },
		sprouts:       map[string]string{},
		seenSigs:      map[string]bool{},
	}, nil
}

func (f *farmer) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", f.enroll)
	mux.HandleFunc("POST /v1/refresh", f.refresh)
	mux.HandleFunc("GET /_stub/state", f.state)
	mux.HandleFunc("GET /v1/sprout/update-manifest", f.updateManifest)
	mux.HandleFunc("POST /_stub/release", f.release)
	mux.HandleFunc("POST /_stub/selfupdate", f.selfUpdate)
	mux.HandleFunc("GET /_stub/fleet", f.fleetReport)
	return mux
}

func enrollmentFailed(w http.ResponseWriter, reason string) {
	log.Printf("enroll: rejected: %s", reason)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"enrollment_failed"}`))
}

// checkSig verifies sigB64 (unpadded base64url) is nkeyPub's signature over
// payload, within maxSkew of timestamp, and not seen before.
func (f *farmer) checkSig(nkeyPub string, timestamp int64, sigB64 string, payload []byte) error {
	if d := f.now().Sub(time.Unix(timestamp, 0)); d > maxSkew || d < -maxSkew {
		return fmt.Errorf("timestamp %d outside the allowed skew", timestamp)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return errors.New("nkey_sig is not unpadded base64url")
	}
	kp, err := nkeys.FromPublicKey(nkeyPub)
	if err != nil {
		return err
	}
	if err := kp.Verify(payload, sig); err != nil {
		return err
	}
	if f.seenSigs[sigB64] {
		return errors.New("signed request replayed")
	}
	f.seenSigs[sigB64] = true
	return nil
}

func (f *farmer) enroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		enrollmentFailed(w, "bad body: "+err.Error())
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrollRequests++
	if !nkeys.IsValidPublicUserKey(req.NKeyPub) {
		enrollmentFailed(w, "malformed nkey_pub")
		return
	}
	sproutBoxPub, err := pki.DecodeBoxPubKey(req.SproutPub)
	if err != nil {
		enrollmentFailed(w, "malformed sprout_pub")
		return
	}
	payload := pki.EnrollSigningPayload(req.Timestamp, req.NKeyPub, req.Hostname, req.SproutPub, req.JoinToken)
	if err := f.checkSig(req.NKeyPub, req.Timestamp, req.NKeySig, payload); err != nil {
		enrollmentFailed(w, "proof of possession: "+err.Error())
		return
	}
	sproutID, enrolled := f.sprouts[req.NKeyPub]
	if !enrolled {
		if subtle.ConstantTimeCompare([]byte(req.JoinToken), []byte(f.joinToken)) != 1 {
			enrollmentFailed(w, "wrong join token")
			return
		}
		if f.redemptions >= f.maxUses {
			enrollmentFailed(w, "join token exhausted")
			return
		}
		sproutID = strings.ReplaceAll(strings.ToLower(req.Hostname), "_", "-")
		if !pki.IsValidSproutID(sproutID) {
			enrollmentFailed(w, "bad hostname")
			return
		}
		f.redemptions++
		f.sprouts[req.NKeyPub] = sproutID
		log.Printf("enroll: sprout %s enrolled (redemption %d of %d)", sproutID, f.redemptions, f.maxUses)
	} else {
		log.Printf("enroll: replayed sprout %s", sproutID)
	}
	f.sproutBox[sproutID] = sproutBoxPub
	userJWT, gatewayJWT, err := f.mint(req.NKeyPub, sproutID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, pki.EnrollResponse{
		SproutID:        sproutID,
		JWT:             userJWT,
		GatewayJWT:      gatewayJWT,
		NKeyIdentity:    req.NKeyPub,
		TenantX25519Pub: f.tenantBoxPK,
		NatsURLs:        f.natsURLs,
	})
}

func (f *farmer) refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		enrollmentFailed(w, "bad body: "+err.Error())
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	sproutID, ok := f.sprouts[req.NKeyPub]
	if !ok {
		enrollmentFailed(w, "refresh from an unknown nkey_pub")
		return
	}
	if err := f.checkSig(req.NKeyPub, req.Timestamp, req.NKeySig, pki.RefreshSigningPayload(req.Timestamp, req.NKeyPub)); err != nil {
		enrollmentFailed(w, "refresh proof of possession: "+err.Error())
		return
	}
	userJWT, gatewayJWT, err := f.mint(req.NKeyPub, sproutID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, pki.RefreshResponse{
		SproutID:        sproutID,
		JWT:             userJWT,
		GatewayJWT:      gatewayJWT,
		NKeyIdentity:    req.NKeyPub,
		TenantX25519Pub: f.tenantBoxPK,
	})
}

// mint returns a NATS User JWT (under the stub's one account, with no
// permission limits) and a gateway JWT for nkeyPub.
func (f *farmer) mint(nkeyPub, sproutID string) (string, string, error) {
	uc := natsjwt.NewUserClaims(nkeyPub)
	uc.Name = sproutID
	userJWT, err := uc.Encode(f.account)
	if err != nil {
		return "", "", err
	}
	now := f.now()
	tok, err := jwxjwt.NewBuilder().
		Subject(nkeyPub).
		Issuer("imas-stubfarmer").
		IssuedAt(now).
		Expiration(now.Add(24*time.Hour)).
		Claim("tenant_id", stubTenantID).
		Claim("sprout_id", sproutID).
		Build()
	if err != nil {
		return "", "", err
	}
	signed, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwa.EdDSA, f.gatewayKey))
	if err != nil {
		return "", "", err
	}
	return userJWT, string(signed), nil
}

func (f *farmer) state(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	st := State{
		Redemptions:    f.redemptions,
		EnrollRequests: f.enrollRequests,
		Sprouts:        map[string]string{},
	}
	for k, v := range f.sprouts {
		st.Sprouts[k] = v
	}
	f.mu.Unlock()
	st.Connected = f.connected()
	if st.Connected == nil {
		st.Connected = []string{}
	}
	writeJSON(w, st)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// tlsMaterial is a throwaway CA and a server certificate it issued for
// hosts.
type tlsMaterial struct {
	caPEM []byte
	cert  tls.Certificate
}

func newTLSMaterial(hosts []string) (*tlsMaterial, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "imas stubfarmer test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(7 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return &tlsMaterial{
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		cert:  tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key, Leaf: nil},
	}, nil
}

// startBus runs an operator-mode nats-server that trusts f's account.
func startBus(f *farmer, host string, port int, tm *tlsMaterial) (*server.Server, error) {
	operator, err := nkeys.CreateOperator()
	if err != nil {
		return nil, err
	}
	opPub, _ := operator.PublicKey()
	opClaims := natsjwt.NewOperatorClaims(opPub)
	opClaims.Name = "imas-stubfarmer"
	sys, err := nkeys.CreateAccount()
	if err != nil {
		return nil, err
	}
	sysPub, _ := sys.PublicKey()
	opClaims.SystemAccount = sysPub
	opJWT, err := opClaims.Encode(operator)
	if err != nil {
		return nil, err
	}
	opClaims, err = natsjwt.DecodeOperatorClaims(opJWT)
	if err != nil {
		return nil, err
	}
	resolver := &server.MemAccResolver{}
	for name, kp := range map[string]nkeys.KeyPair{"SYS": sys, "tenant": f.account} {
		pub, _ := kp.PublicKey()
		ac := natsjwt.NewAccountClaims(pub)
		ac.Name = name
		acJWT, err := ac.Encode(operator)
		if err != nil {
			return nil, err
		}
		if err := resolver.Store(pub, acJWT); err != nil {
			return nil, err
		}
	}
	opts := &server.Options{
		Host:             host,
		Port:             port,
		NoSigs:           true,
		TrustedOperators: []*natsjwt.OperatorClaims{opClaims},
		SystemAccount:    sysPub,
		AccountResolver:  resolver,
		TLSConfig:        &tls.Config{Certificates: []tls.Certificate{tm.cert}, MinVersion: tls.VersionTLS12},
		TLS:              true,
		TLSTimeout:       5,
	}
	s, err := server.NewServer(opts)
	if err != nil {
		return nil, err
	}
	go s.Start()
	if !s.ReadyForConnections(10 * time.Second) {
		return nil, errors.New("nats-server did not become ready")
	}
	return s, nil
}

// connectedNKeys lists the NKeys of the bus's client connections.
func connectedNKeys(s *server.Server) []string {
	connz, err := s.Connz(&server.ConnzOptions{Username: true})
	if err != nil {
		log.Printf("connz: %v", err)
		return nil
	}
	var out []string
	for _, c := range connz.Conns {
		// For a JWT-authenticated client this is its NKey.
		if c.AuthorizedUser != "" {
			out = append(out, c.AuthorizedUser)
		}
	}
	return out
}

func main() {
	addr := flag.String("addr", ":5405", "HTTPS listen address (enrollment API)")
	natsHost := flag.String("nats-host", "0.0.0.0", "bus listen host")
	natsPort := flag.Int("nats-port", 5406, "bus listen port")
	hosts := flag.String("hosts", "localhost", "comma-separated names/IPs the TLS certificate covers")
	busURLs := flag.String("nats-urls", "", "comma-separated nats_urls returned at enrollment (empty: none)")
	joinToken := flag.String("join-token", "", "the one join token this farmer accepts, {key_id}.{secret}")
	maxUses := flag.Int("max-uses", 10, "how many first-time enrollments the join token allows")
	stateDir := flag.String("state-dir", ".", "where ca.pem is written")
	staticDir := flag.String("static-dir", "", "directory to serve over plain HTTP (empty: none)")
	staticAddr := flag.String("static-addr", ":8080", "listen address for -static-dir")
	repoProxyTo := flag.String("repo-proxy-to", "", "package repository to front with TLS (e.g. http://nexus:8081; empty: none)")
	repoProxyAddr := flag.String("repo-proxy-addr", ":8443", "HTTPS listen address for -repo-proxy-to")
	repoHosts := flag.String("repo-hosts", "localhost", "comma-separated names/IPs the repository proxy's certificate covers")
	flag.Parse()
	if *joinToken == "" {
		log.Fatal("-join-token is required")
	}
	var urls []string
	if *busURLs != "" {
		urls = strings.Split(*busURLs, ",")
	}
	if _, err := pki.ValidateBusURLs(urls); err != nil {
		log.Fatalf("-nats-urls: %v", err)
	}
	f, err := newFarmer(*joinToken, *maxUses, urls)
	if err != nil {
		log.Fatal(err)
	}
	tm, err := newTLSMaterial(strings.Split(*hosts, ","))
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(*stateDir, 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*stateDir, "ca.pem"), tm.caPEM, 0o644); err != nil {
		log.Fatal(err)
	}
	bus, err := startBus(f, *natsHost, *natsPort, tm)
	if err != nil {
		log.Fatal(err)
	}
	f.connected = func() []string { return connectedNKeys(bus) }
	if err := os.WriteFile(filepath.Join(*stateDir, "fleet-signing-keys.json"), f.fleet.keyringJSON(), 0o644); err != nil {
		log.Fatal(err)
	}
	if f.nc, err = f.connectBus(strings.Split(*hosts, ",")[0], *natsPort, tm); err != nil {
		log.Fatal(err)
	}
	if err := f.watchBus(f.nc); err != nil {
		log.Fatal(err)
	}
	if *repoProxyTo != "" {
		if err := startRepoProxy(*repoProxyTo, *repoProxyAddr, strings.Split(*repoHosts, ","), *stateDir); err != nil {
			log.Fatal(err)
		}
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           f.routes(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{tm.cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("stubfarmer: enrollment API on %s, bus on %s:%d", *addr, *natsHost, *natsPort)
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	if *staticDir != "" {
		static := &http.Server{Addr: *staticAddr, Handler: http.FileServer(http.Dir(*staticDir)), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			log.Printf("stubfarmer: serving %s on %s", *staticDir, *staticAddr)
			if err := static.ListenAndServe(); err != nil {
				log.Fatal(err)
			}
		}()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	_ = srv.Shutdown(context.Background())
	f.nc.Close()
	bus.Shutdown()
}

// connectBus connects the stub itself to its bus as a User in the tenant
// account, over TLS verified against its own CA.
func (f *farmer) connectBus(serverName string, port int, tm *tlsMaterial) (*nats.Conn, error) {
	user, err := nkeys.CreateUser()
	if err != nil {
		return nil, err
	}
	userPub, _ := user.PublicKey()
	uc := natsjwt.NewUserClaims(userPub)
	uc.Name = "stubfarmer"
	userJWT, err := uc.Encode(f.account)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(tm.caPEM)
	return nats.Connect(fmt.Sprintf("tls://127.0.0.1:%d", port),
		nats.UserJWT(func() (string, error) { return userJWT, nil }, func(nonce []byte) ([]byte, error) { return user.Sign(nonce) }),
		nats.Secure(&tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12}),
		nats.MaxReconnects(-1))
}

// startRepoProxy fronts target with TLS from a new CA, written to
// stateDir/repo-ca.pem.
func startRepoProxy(target, addr string, hosts []string, stateDir string) error {
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	tm, err := newTLSMaterial(hosts)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stateDir, "repo-ca.pem"), tm.caPEM, 0o644); err != nil {
		return err
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("repo: %s %s (auth: %s)", r.Method, r.URL.Path, authSummary(r))
			proxy.ServeHTTP(w, r)
		}),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{tm.cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("stubfarmer: TLS proxy for %s on %s", target, addr)
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	return nil
}

// authSummary names a request's credentials without revealing them:
// "none", "basic:<user>", "bearer", or "other".
func authSummary(r *http.Request) string {
	h := r.Header.Get("Authorization")
	switch {
	case h == "":
		return "none"
	case strings.HasPrefix(h, "Bearer "):
		return "bearer"
	}
	if user, _, ok := r.BasicAuth(); ok {
		return "basic:" + user
	}
	return "other"
}
