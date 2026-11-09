package mysqldsn

import (
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Bounds on how long farmer and saasapi wait on a database peer that has
// gone without closing its connections (UAT Run 3 on v0.1.0-rc.23, HA2).
//
// Both services reach PXC through the HAProxy Service. When a core node
// dies abruptly (a VM stopped, not drained), the HAProxy and PXC pods on it
// send neither a FIN nor a reset, so:
//
//   - a pooled connection that went through that node's HAProxy pod looks
//     alive; a query on it waited for the kernel to give up on the socket
//     (tcp_retries2, about 15 minutes), and an idle one was found dead only
//     by Go's TCP keepalive, 15 s + 9 × 15 s = 150 s after the node died;
//   - a new connection opened before Kubernetes removed that pod's
//     endpoint waited on SYN retries for up to about 2 minutes, since the
//     DSNs set no dial timeout.
//
// In HA2, cmd.run was not served for 2m17s against a 60 s window while
// PXC itself failed over in about 33 s. These bounds turn each hang into
// an error the caller retries on a healthy connection.
const (
	// DialTimeout bounds opening a connection.
	DialTimeout = 5 * time.Second
	// ReadTimeout bounds waiting for the server's answer. It stays above
	// InnoDB's lock wait (innodb_lock_wait_timeout, 50 s by default, which
	// the chart does not change): a slow lock wait must still end in
	// MySQL error 1205, which internal/pki/dbretry.go retries, not in an
	// I/O timeout.
	ReadTimeout = 60 * time.Second
	// WriteTimeout bounds sending a query.
	WriteTimeout = 30 * time.Second
	// ConnMaxIdleTime closes a connection idle this long, so one to a peer
	// that died while it sat in the pool is dropped, not handed out.
	ConnMaxIdleTime = 30 * time.Second
	// ConnMaxLifetime recycles every connection, so all of them are
	// re-dialled (and re-balanced over the HAProxy pods) after a failover.
	ConnMaxLifetime = 5 * time.Minute
)

// WithIOTimeouts returns dsn with the driver's timeout, readTimeout and
// writeTimeout set to DialTimeout, ReadTimeout and WriteTimeout where dsn
// leaves them unset; a value the DSN sets is kept, so an operator can
// still choose another. setting names where the DSN came from, for the
// message. The DSN itself is never echoed: it holds the password.
func WithIOTimeouts(setting, dsn string) (string, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return "", fmt.Errorf("%s is not a valid MySQL DSN: %w", setting, err)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DialTimeout
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = ReadTimeout
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = WriteTimeout
	}
	return cfg.FormatDSN(), nil
}

// Pool is the part of *sql.DB ConfigurePool sets.
type Pool interface {
	SetConnMaxIdleTime(d time.Duration)
	SetConnMaxLifetime(d time.Duration)
}

// ConfigurePool sets ConnMaxIdleTime and ConnMaxLifetime on p.
func ConfigurePool(p Pool) {
	p.SetConnMaxIdleTime(ConnMaxIdleTime)
	p.SetConnMaxLifetime(ConnMaxLifetime)
}
