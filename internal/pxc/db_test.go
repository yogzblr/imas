package pxc

import (
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/mysqldsn"
)

func TestOpenDBEmptyDSN(t *testing.T) {
	if _, err := OpenDB(""); err == nil {
		t.Error("expected an error for an empty DSN")
	}
}

// Security review 2026-10, I1: farmer refuses to start on a DSN whose loc
// is not UTC, naming the setting, before it connects to anything.
func TestOpenDBRefusesNonUTCLoc(t *testing.T) {
	const secret = "s3cr3t-pw"
	for _, dsn := range []string{
		"farmer_svc:" + secret + "@tcp(pxc:3306)/farmer?parseTime=true&loc=Local",
		"farmer_svc:" + secret + "@tcp(pxc:3306)/farmer?parseTime=true&charset=utf8mb4&loc=Asia%2FKolkata",
	} {
		_, err := OpenDB(dsn)
		if err == nil || !strings.Contains(err.Error(), "IMAS_PXC_DSN") || !strings.Contains(err.Error(), "loc=UTC") {
			t.Errorf("OpenDB(%q) = %v, want an error naming IMAS_PXC_DSN and loc=UTC", dsn, err)
		}
		if err != nil && strings.Contains(err.Error(), secret) {
			t.Errorf("error carries the password: %v", err)
		}
	}
}

// UAT HA2 (v0.1.0-rc.23): a database peer that vanished without a reset
// left a new connection waiting on SYN retries for about two minutes,
// since the DSN set no dial timeout. OpenDB now gives up after
// mysqldsn.DialTimeout. 192.0.2.1 (TEST-NET-1) never answers; where the
// host has no route to it the error comes at once, which passes too.
func TestOpenDBGivesUpOnAPeerThatNeverAnswers(t *testing.T) {
	if testing.Short() {
		t.Skip("waits up to the dial timeout")
	}
	start := time.Now()
	_, err := OpenDB("farmer_svc:pw@tcp(192.0.2.1:3306)/farmer?parseTime=true&loc=UTC")
	took := time.Since(start)
	if err == nil {
		t.Fatal("OpenDB connected to an address that never answers")
	}
	if limit := 3 * mysqldsn.DialTimeout; took > limit {
		t.Errorf("OpenDB took %v to give up, more than %v", took.Round(time.Second), limit)
	}
}
