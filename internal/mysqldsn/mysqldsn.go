// Package mysqldsn checks the go-sql-driver/mysql DSNs farmer and saasapi
// open PXC with (security review 2026-10, I1).
//
// The row leases (internal/lease, internal/saasapi/outbox_lease.go) and
// every other DATETIME column the two services share are written and
// compared as times from the application, not the database's NOW(): the
// lease clock is replaceable, and the unit tests drive it over sqlite,
// which has no NOW(3). The driver converts each time with the DSN's loc,
// so two processes with different locs would read the same lease_until
// hours apart, and one of them could take a lease the other still holds.
// Both services therefore refuse to start unless loc is UTC (or absent:
// the driver's default is UTC).
package mysqldsn

import (
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
)

// RequireUTC parses dsn and returns an error unless its loc is UTC.
// setting names where the DSN came from (an environment variable or a
// config key), for the message. The DSN itself is never echoed: it holds
// the password.
func RequireUTC(setting, dsn string) error {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return fmt.Errorf("%s is not a valid MySQL DSN: %w", setting, err)
	}
	if cfg.Loc != nil && cfg.Loc != time.UTC {
		return fmt.Errorf("%s sets loc=%s; it must be loc=UTC (or no loc, the driver's default): farmer and saasapi write and compare the shared lease and DATETIME columns as UTC (the Helm chart's database.params sets loc=UTC)", setting, cfg.Loc)
	}
	return nil
}
