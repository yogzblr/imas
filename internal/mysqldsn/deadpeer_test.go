package mysqldsn

import (
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func TestWithIOTimeoutsAddsTheBounds(t *testing.T) {
	const secret = "s3cr3t-pw"
	in := "u:" + secret + "@tcp(imas-core-pxc-haproxy.imas-core.svc.cluster.local:3306)/saas?parseTime=true&charset=utf8mb4&loc=UTC"
	out, err := WithIOTimeouts("SAASAPI_DSN", in)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := mysql.ParseDSN(out)
	if err != nil {
		t.Fatalf("the result does not parse: %v", err)
	}
	if cfg.Timeout != DialTimeout || cfg.ReadTimeout != ReadTimeout || cfg.WriteTimeout != WriteTimeout {
		t.Errorf("timeouts = %v/%v/%v, want %v/%v/%v", cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout, DialTimeout, ReadTimeout, WriteTimeout)
	}
	// Everything else the DSN said is kept.
	if cfg.User != "u" || cfg.Passwd != secret || cfg.Addr != "imas-core-pxc-haproxy.imas-core.svc.cluster.local:3306" || cfg.DBName != "saas" {
		t.Errorf("user, address or schema changed: %s@%s/%s", cfg.User, cfg.Addr, cfg.DBName)
	}
	if !cfg.ParseTime {
		t.Error("parseTime=true was dropped")
	}
	if !strings.Contains(out, "charset=utf8mb4") {
		t.Error("charset=utf8mb4 was dropped")
	}
	if err := RequireUTC("SAASAPI_DSN", out); err != nil {
		t.Errorf("the result fails RequireUTC: %v", err)
	}
}

func TestWithIOTimeoutsKeepsTheOperatorsValues(t *testing.T) {
	out, err := WithIOTimeouts("IMAS_PXC_DSN", "u:p@tcp(pxc:3306)/farmer?parseTime=true&timeout=2s&readTimeout=90s&writeTimeout=10s")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := mysql.ParseDSN(out)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != 2*time.Second || cfg.ReadTimeout != 90*time.Second || cfg.WriteTimeout != 10*time.Second {
		t.Errorf("timeouts = %v/%v/%v, want the DSN's 2s/1m30s/10s", cfg.Timeout, cfg.ReadTimeout, cfg.WriteTimeout)
	}
}

func TestWithIOTimeoutsRefusesABadDSNWithoutEchoingIt(t *testing.T) {
	const secret = "s3cr3t-pw"
	_, err := WithIOTimeouts("IMAS_PXC_DSN", "u:"+secret+"@tcp(pxc:3306)farmer")
	if err == nil {
		t.Fatal("a DSN that does not parse was accepted")
	}
	if !strings.Contains(err.Error(), "IMAS_PXC_DSN") {
		t.Errorf("error %q does not name the setting", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error %q echoes the password", err)
	}
}

// The read timeout must outlast InnoDB's default lock wait, or a slow lock
// wait ends in an I/O error that internal/pki/dbretry.go does not retry.
func TestReadTimeoutOutlastsTheLockWait(t *testing.T) {
	const innodbLockWaitDefault = 50 * time.Second
	if ReadTimeout <= innodbLockWaitDefault {
		t.Errorf("ReadTimeout %v is not above innodb_lock_wait_timeout's default %v", ReadTimeout, innodbLockWaitDefault)
	}
}

type fakePool struct{ idle, life time.Duration }

func (p *fakePool) SetConnMaxIdleTime(d time.Duration) { p.idle = d }
func (p *fakePool) SetConnMaxLifetime(d time.Duration) { p.life = d }

func TestConfigurePool(t *testing.T) {
	var p fakePool
	ConfigurePool(&p)
	if p.idle != ConnMaxIdleTime || p.life != ConnMaxLifetime {
		t.Errorf("pool idle/lifetime = %v/%v, want %v/%v", p.idle, p.life, ConnMaxIdleTime, ConnMaxLifetime)
	}
	if p.idle <= 0 || p.life <= 0 {
		t.Error("a zero bound leaves dead connections in the pool")
	}
}
