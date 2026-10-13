package harness

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	natsjwt "github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
)

// testCA makes a CA and a server certificate for 127.0.0.1 under it.
func testCA(t *testing.T) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "uat-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "bus"},
		DNSNames: []string{"imas-dmz-nats-bus.imas-dmz.svc"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// busNode starts a nats-server in operator mode holding one account,
// whose claims revoke the listed user keys.
func busNode(t *testing.T, cert tls.Certificate, akp nkeys.KeyPair, revoke ...string) string {
	t.Helper()
	okp, _ := nkeys.CreateOperator()
	opub, _ := okp.PublicKey()
	oc := natsjwt.NewOperatorClaims(opub)
	ojwt, err := oc.Encode(okp)
	if err != nil {
		t.Fatal(err)
	}
	opc, err := natsjwt.DecodeOperatorClaims(ojwt)
	if err != nil {
		t.Fatal(err)
	}
	apub, _ := akp.PublicKey()
	ac := natsjwt.NewAccountClaims(apub)
	for _, r := range revoke {
		ac.Revoke(r)
	}
	ajwt, err := ac.Encode(okp)
	if err != nil {
		t.Fatal(err)
	}
	res := &natsserver.MemAccResolver{}
	if err := res.Store(apub, ajwt); err != nil {
		t.Fatal(err)
	}
	opts := &natsserver.Options{
		Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TrustedOperators: []*natsjwt.OperatorClaims{opc}, AccountResolver: res,
		TLS: true, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("nats-server did not start")
	}
	t.Cleanup(srv.Shutdown)
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(srv.Addr().(*net.TCPAddr).Port))
}

// enrolledUnder is an Enrolment whose User JWT the account signed.
func enrolledUnder(t *testing.T, akp nkeys.KeyPair) *Enrolment {
	t.Helper()
	e, err := NewEnrolment("uat-ha-test", "k.s")
	if err != nil {
		t.Fatal(err)
	}
	uc := natsjwt.NewUserClaims(e.NKeyPub)
	if e.userJWT, err = uc.Encode(akp); err != nil {
		t.Fatal(err)
	}
	return e
}

// busName is the bus Service name on testCA's certificate.
const busName = "imas-dmz-nats-bus.imas-dmz.svc"

func TestBusConnect(t *testing.T) {
	pool, cert := testCA(t)
	akp, _ := nkeys.CreateAccount()
	e := enrolledUnder(t, akp)
	c, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if err := BusConnect(c, busNode(t, cert, akp), busName, pool, e); err != nil {
		t.Fatalf("a sprout of a known account must be accepted: %v", err)
	}
	err := BusConnect(c, busNode(t, cert, akp, e.NKeyPub), busName, pool, e)
	if !errors.Is(err, ErrBusRefused) {
		t.Fatalf("a revoked sprout must be refused with ErrBusRefused, got %v", err)
	}
	other, _ := nkeys.CreateAccount()
	if err := BusConnect(c, busNode(t, cert, other), busName, pool, e); !errors.Is(err, ErrBusRefused) {
		t.Fatalf("a sprout of an account the node lacks must be refused, got %v", err)
	}
	otherPool, _ := testCA(t)
	err = BusConnect(c, busNode(t, cert, akp), busName, otherPool, e)
	if err == nil || errors.Is(err, ErrBusRefused) {
		t.Fatalf("a node whose certificate the CA did not sign is a connection error, not a refusal: %v", err)
	}
	err = BusConnect(c, busNode(t, cert, akp), "other.imas-dmz.svc", pool, e)
	if err == nil || errors.Is(err, ErrBusRefused) {
		t.Fatalf("a certificate without the server name is a connection error, not a refusal: %v", err)
	}
	if err := BusConnect(c, busNode(t, cert, akp), "", pool, e); err == nil {
		t.Fatal("no server name must be refused")
	}
}
