package main

// The local bus: one node, run as a child process of the harness so that
// it can be restarted mid-run and so that its CPU and memory are its own,
// not the load generator's. The child builds its server the way
// cmd/farmerbus builds a single node: pki.ConfigureBusNats for the
// options (TLS-only listener, operator trust, a full resolver seeded with
// nothing but the SYS bootstrap Account), the same logger with debug and
// trace on, and a graceful Shutdown on SIGTERM. The cluster code and its
// fence live in cmd/farmerbus's main package and are not reused here;
// clustered runs go against deployed nodes (-servers).

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	nats_server "github.com/nats-io/nats-server/v2/server"

	"github.com/yogzblr/imas/internal/config"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
)

// The child is selected by environment rather than a subcommand so that
// a test binary can be its own child too (see TestMain).
const (
	envRole    = "IMAS_LOADTEST_ROLE"
	roleBus    = "bus-node"
	envBusDir  = "IMAS_LOADTEST_BUS_DIR"
	envBusHost = "IMAS_LOADTEST_BUS_HOST"
	envBusPort = "IMAS_LOADTEST_BUS_PORT"
	// envBusTrace "off" turns NATS debug and trace logging off.
	envBusTrace = "IMAS_LOADTEST_BUS_TRACE"
	busReady    = "IMAS-LOADTEST-BUS-READY"
)

// writeBusCerts issues a CA and a server certificate for host (and
// 127.0.0.1/localhost) into dir, and returns the CA pool clients pin.
func writeBusCerts(dir, host string) (*x509.CertPool, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "imas loadtest CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(7 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
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
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "imas loadtest bus"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(7 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.Equal(net.ParseIP("127.0.0.1")) && !ip.IsUnspecified() {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	} else if host != "localhost" {
		tmpl.DNSNames = append(tmpl.DNSNames, host)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	for name, block := range map[string]*pem.Block{
		"ca.pem":   {Type: "CERTIFICATE", Bytes: caDER},
		"cert.pem": {Type: "CERTIFICATE", Bytes: der},
		"key.pem":  {Type: "EC PRIVATE KEY", Bytes: keyDER},
	} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o600); err != nil {
			return nil, err
		}
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, nil
}

// localBus runs and restarts the child bus process.
type localBus struct {
	exe   string
	dir   string
	host  string
	port  int
	seeds seedFiles
	trace bool

	mu      sync.Mutex
	cmd     *exec.Cmd
	exited  chan struct{}
	logFile *os.File
}

// newLocalBus prepares dir (certificates, PKI directory) for a child bus
// listening on host:port; port 0 picks a free one, kept across restarts.
func newLocalBus(dir, host string, port int, seeds seedFiles, trace bool) (*localBus, *x509.CertPool, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	pool, err := writeBusCerts(dir, host)
	if err != nil {
		return nil, nil, fmt.Errorf("writing bus certificates: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "pki"), 0o700); err != nil {
		return nil, nil, err
	}
	if port == 0 {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			return nil, nil, err
		}
		port = ln.Addr().(*net.TCPAddr).Port
		ln.Close()
	}
	lf, err := os.OpenFile(filepath.Join(dir, "bus.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return &localBus{exe: exe, dir: dir, host: host, port: port, seeds: seeds, trace: trace, logFile: lf}, pool, nil
}

func (b *localBus) URL() string {
	return "tls://" + net.JoinHostPort(b.host, strconv.Itoa(b.port))
}

// PID is the running child's process ID, or 0.
func (b *localBus) PID() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cmd == nil || b.cmd.Process == nil {
		return 0
	}
	return b.cmd.Process.Pid
}

// Start launches the child and waits until it accepts connections.
func (b *localBus) Start(ctx context.Context) error {
	cmd := exec.Command(b.exe)
	cmd.Env = append(os.Environ(),
		envRole+"="+roleBus,
		envBusDir+"="+b.dir,
		envBusHost+"="+b.host,
		envBusPort+"="+strconv.Itoa(b.port),
	)
	if !b.trace {
		cmd.Env = append(cmd.Env, envBusTrace+"=off")
	}
	for name, path := range b.seeds {
		cmd.Env = append(cmd.Env, "IMAS_NATS_"+name+"_SEED_FILE="+path)
	}
	cmd.Stderr = b.logFile
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan struct{})
	ready := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(out)
		signalled := false
		for sc.Scan() {
			if !signalled && strings.TrimSpace(sc.Text()) == busReady {
				close(ready)
				signalled = true
			}
		}
	}()
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	b.mu.Lock()
	b.cmd, b.exited = cmd, exited
	b.mu.Unlock()
	select {
	case <-ready:
		return nil
	case <-exited:
		return fmt.Errorf("local bus exited before it was ready; see %s", filepath.Join(b.dir, "bus.log"))
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		return errors.New("local bus not ready after 30s")
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		return ctx.Err()
	}
}

// Stop sends sig to the child and waits for it to exit, killing it after
// 30s.
func (b *localBus) Stop(sig syscall.Signal) error {
	b.mu.Lock()
	cmd, exited := b.cmd, b.exited
	b.cmd = nil
	b.mu.Unlock()
	if cmd == nil {
		return nil
	}
	if err := cmd.Process.Signal(sig); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-exited:
		return nil
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-exited
		return errors.New("local bus did not stop within 30s; killed")
	}
}

// Close stops the child and closes its log.
func (b *localBus) Close() {
	_ = b.Stop(syscall.SIGTERM)
	b.logFile.Close()
}

// runBusNode is the child: one bus node, until SIGTERM or SIGINT.
func runBusNode() error {
	dir := os.Getenv(envBusDir)
	config.FarmerInterface = os.Getenv(envBusHost)
	config.FarmerBusPort = os.Getenv(envBusPort)
	config.FarmerWSPort = ""
	config.FarmerPKI = filepath.Join(dir, "pki")
	config.RootCA = filepath.Join(dir, "ca.pem")
	config.CertFile = filepath.Join(dir, "cert.pem")
	config.KeyFile = filepath.Join(dir, "key.pem")
	// farmer's default "loglevel".
	log.SetLogLevel(log.LInfo)

	opts, _ := pki.ConfigureBusNats()
	// A fixed name, so the node reads as one bus across restarts in the
	// varz samples. A single farmerbus node leaves it unset (its ID).
	opts.ServerName = "loadtest-bus"
	trace := os.Getenv(envBusTrace) != "off"
	opts.Trace, opts.Debug = trace, trace
	srv, err := nats_server.NewServer(&opts)
	if err != nil {
		return err
	}
	// As cmd/farmerbus's startBus: the internal logger, debug and trace
	// on (unless -bus-trace=false, to measure what they cost).
	var natsLogger log.Logger
	srv.SetLogger(natsLogger, trace, trace)
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		srv.Shutdown()
		return errors.New("NATS server did not start listening")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Println(busReady)
	<-ctx.Done()
	srv.Shutdown()
	srv.WaitForShutdown()
	log.Flush()
	return nil
}
