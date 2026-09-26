package sdb

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yogzblr/imas/internal/log"
)

// DefaultCertWatchInterval is how often a CertWatcher re-stats its cert and
// key files for changes when no explicit interval is given.
const DefaultCertWatchInterval = 30 * time.Second

// CertWatcher hot-reloads a client certificate/key pair from disk so that a
// rotated credential is picked up without a process restart. Rotation of
// the underlying files (e.g. a customer's Vault client cert) is entirely
// out of imas's control; CertWatcher only makes picking up the new files
// painless once they land.
//
// Use GetClientCertificate as a tls.Config.GetClientCertificate callback.
type CertWatcher struct {
	certFile string
	keyFile  string
	interval time.Duration

	cert atomic.Pointer[tls.Certificate]

	mu          sync.Mutex
	certModTime time.Time
	keyModTime  time.Time

	stop     chan struct{}
	stopOnce sync.Once
}

// NewCertWatcher loads certFile/keyFile once synchronously and starts a
// background goroutine that reloads them whenever their mtimes change. A
// zero interval uses DefaultCertWatchInterval. Call Close to stop the
// background goroutine.
func NewCertWatcher(certFile, keyFile string, interval time.Duration) (*CertWatcher, error) {
	if interval <= 0 {
		interval = DefaultCertWatchInterval
	}
	w := &CertWatcher{
		certFile: certFile,
		keyFile:  keyFile,
		interval: interval,
		stop:     make(chan struct{}),
	}
	if err := w.reload(); err != nil {
		return nil, err
	}
	go w.watch()
	return w, nil
}

func (w *CertWatcher) reload() error {
	cert, err := tls.LoadX509KeyPair(w.certFile, w.keyFile)
	if err != nil {
		return fmt.Errorf("loading client cert/key: %w", err)
	}
	certStat, err := os.Stat(w.certFile)
	if err != nil {
		return fmt.Errorf("stat client cert: %w", err)
	}
	keyStat, err := os.Stat(w.keyFile)
	if err != nil {
		return fmt.Errorf("stat client key: %w", err)
	}
	w.cert.Store(&cert)
	w.mu.Lock()
	w.certModTime = certStat.ModTime()
	w.keyModTime = keyStat.ModTime()
	w.mu.Unlock()
	return nil
}

func (w *CertWatcher) changed() bool {
	certStat, err := os.Stat(w.certFile)
	if err != nil {
		return false
	}
	keyStat, err := os.Stat(w.keyFile)
	if err != nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return !certStat.ModTime().Equal(w.certModTime) || !keyStat.ModTime().Equal(w.keyModTime)
}

func (w *CertWatcher) watch() {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-ticker.C:
			if !w.changed() {
				continue
			}
			if err := w.reload(); err != nil {
				log.Warnf("sdb: failed to reload rotated cert %s: %v", w.certFile, err)
				continue
			}
			log.Infof("sdb: reloaded rotated client cert %s", w.certFile)
		}
	}
}

// GetClientCertificate satisfies tls.Config.GetClientCertificate, always
// returning the most recently loaded certificate.
func (w *CertWatcher) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return w.cert.Load(), nil
}

// Close stops the background reload goroutine. Safe to call more than
// once.
func (w *CertWatcher) Close() {
	w.stopOnce.Do(func() {
		close(w.stop)
	})
}
