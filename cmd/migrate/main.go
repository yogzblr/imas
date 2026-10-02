// Command migrate owns the schemas of imas's PXC cluster: it creates the
// farmer and saas schemas and their users, applies their grants, and runs
// each schema's versioned migrations (internal/migrations) as that
// schema's own user. See docs/design/cloudxp-machine-manager-api-design.md
// §4.1 (grants) and §4.1a (migrations).
//
//	migrate up      root step, both migration sets, then farmer's
//	                enrollment_keys column grant
//	migrate check   exit 0 only if both schemas are within the range this
//	                binary supports; changes nothing (helm rollback)
//
// FLAG FOR SECURITY REVIEW: `up` holds PXC's root credentials and defines
// the single-writer grants. Credentials are read from the environment or
// from files, never from argv, and neither a DSN nor a password is ever
// logged.
package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-sql-driver/mysql"

	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/migrations"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop()
	log.Flush()
	os.Exit(code)
}

const usage = `usage: migrate <command> [flags]

commands:
  up      create the schemas, users and grants (as PXC root), migrate the
          farmer schema as farmer's user and the saas schema as saasapi's,
          then grant farmer UPDATE (used_count, last_used_at) on
          saas.enrollment_keys
  check   exit 0 if both schemas are within the range this binary
          supports, 1 if not; changes nothing

Credentials come from the environment, or from a file named by the
matching *_FILE variable or --*-file flag; never from argv:
  ` + EnvFarmerDSN + `   farmer's DSN (user:password@tcp(host:port)/schema?params)
  ` + EnvSaasDSN + `     saasapi's DSN
  ` + EnvRootPassword + `  PXC root's password (up only)
  ` + EnvRootUser + `      PXC root's user name (up only, default root)

Run "migrate <command> -h" for the command's flags.
`

// run returns the exit code: 0 on success, 1 when the command failed (for
// check: a schema outside the supported range, or unreadable), 2 for a
// usage or configuration error.
func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "up":
		cfg, err := parseUp(args[1:], getenv, stderr)
		if err != nil {
			return usageError(stderr, err)
		}
		if err := up(ctx, cfg, log.Infof); err != nil {
			log.Errorf("migrate up: %v", err)
			return 1
		}
		log.Infof("migrate up: done")
		return 0
	case "check":
		cfg, err := parseCheck(args[1:], getenv, stderr)
		if err != nil {
			return usageError(stderr, err)
		}
		if err := check(ctx, cfg, stdout, log.Infof); err != nil {
			log.Errorf("migrate check: %v", err)
			return 1
		}
		return 0
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "migrate: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func usageError(stderr io.Writer, err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	fmt.Fprintf(stderr, "migrate: %v\n", err)
	return 2
}

// up runs `migrate up`; see the package comment for the order.
func up(ctx context.Context, cfg upConfig, logf func(string, ...any)) error {
	accts := cfg.accounts()
	if err := accts.Validate(); err != nil {
		return err
	}

	var root *sql.DB
	if cfg.skipRoot {
		logf("skipping the root step (--skip-root): the schemas, users and grants must already exist")
	} else {
		root = sql.OpenDB(mustConnector(migrations.RootConfig(cfg.farmer, cfg.rootUser, cfg.rootPassword)))
		defer root.Close()
		if err := waitForServer(ctx, root, cfg.wait, "PXC as "+cfg.rootUser, logf); err != nil {
			return err
		}
		if err := migrations.Bootstrap(ctx, root, accts); err != nil {
			return fmt.Errorf("root step: %w", err)
		}
		logf("schemas %s and %s, users %s and %s, and their grants are in place",
			accts.Farmer.Schema, accts.Saas.Schema, accts.Farmer.User, accts.Saas.User)
	}

	// Two pools per schema: the lock's heartbeat mustn't queue behind a
	// long DDL statement on the migration pool.
	farmerDB, farmerLockDB := sql.OpenDB(mustConnector(cfg.farmer)), sql.OpenDB(mustConnector(cfg.farmer))
	saasDB, saasLockDB := sql.OpenDB(mustConnector(cfg.saas)), sql.OpenDB(mustConnector(cfg.saas))
	for _, db := range []*sql.DB{farmerDB, farmerLockDB, saasDB, saasLockDB} {
		defer db.Close()
	}
	// The users may have only just been created, through another node.
	if err := waitForServer(ctx, farmerDB, cfg.wait, "PXC as "+accts.Farmer.User, logf); err != nil {
		return err
	}
	if err := waitForServer(ctx, saasDB, cfg.wait, "PXC as "+accts.Saas.User, logf); err != nil {
		return err
	}

	// Each schema's lock is taken as its owner, so the owner stays its only
	// writer; farmer's first, always, so two runs can't deadlock.
	farmerLock, ctx, err := migrations.AcquireLock(ctx, farmerLockDB, cfg.lock, logf)
	if err != nil {
		return fmt.Errorf("farmer schema: %w", err)
	}
	defer releaseLock(ctx, farmerLock, "farmer", logf)
	saasLock, ctx, err := migrations.AcquireLock(ctx, saasLockDB, cfg.lock, logf)
	if err != nil {
		return fmt.Errorf("saas schema: %w", err)
	}
	defer releaseLock(ctx, saasLock, "saas", logf)

	for _, m := range []struct {
		db  *sql.DB
		set migrations.Set
	}{{farmerDB, migrations.Farmer}, {saasDB, migrations.Saas}} {
		res, err := migrations.Up(ctx, m.db, m.set, logf)
		if err != nil {
			return lockAware(ctx, err)
		}
		logf("%s schema at version %d (was %d, applied %d)", m.set.Name(), res.To, res.From, len(res.Applied))
	}

	if root != nil {
		if err := migrations.GrantEnrollmentKeyColumns(ctx, root, accts); err != nil {
			return lockAware(ctx, fmt.Errorf("root step: %w", err))
		}
		logf("granted %s UPDATE (used_count, last_used_at) on %s.enrollment_keys", accts.Farmer.User, accts.Saas.Schema)
	}
	return lockAware(ctx, ctx.Err())
}

// lockAware names a lost lock as the reason a run stopped.
func lockAware(ctx context.Context, err error) error {
	if err != nil && migrations.LockLost(ctx) {
		return fmt.Errorf("lost the migration lock to another run, stopped: %w", err)
	}
	return err
}

func releaseLock(ctx context.Context, l *migrations.Lock, schema string, logf func(string, ...any)) {
	if err := l.Release(ctx); err != nil {
		logf("releasing the %s schema's migration lock: %v (it lapses at the end of its lease)", schema, err)
	}
}

// check runs `migrate check`: reads both schemas' state as their owners
// and checks it against this binary, writing nothing.
func check(ctx context.Context, cfg checkConfig, stdout io.Writer, logf func(string, ...any)) error {
	var failed []string
	for _, m := range []struct {
		cfg *mysql.Config
		set migrations.Set
	}{{cfg.farmer, migrations.Farmer}, {cfg.saas, migrations.Saas}} {
		db := sql.OpenDB(mustConnector(m.cfg))
		defer db.Close()
		if err := waitForServer(ctx, db, cfg.wait, "PXC as "+m.cfg.User, logf); err != nil {
			return err
		}
		st, err := migrations.ReadState(ctx, db)
		if err != nil {
			return fmt.Errorf("%s schema: %w", m.set.Name(), err)
		}
		if err := m.set.Check(st); err != nil {
			fmt.Fprintf(stdout, "%s: NOT SUPPORTED: %v\n", m.set.Name(), err)
			failed = append(failed, m.set.Name())
			continue
		}
		fmt.Fprintf(stdout, "%s: ok: schema version %d, floor %d; this binary is built for %d\n",
			m.set.Name(), st.Version, st.Floor, m.set.Latest())
	}
	if len(failed) > 0 {
		return fmt.Errorf("schemas outside the range this binary supports: %v", failed)
	}
	return nil
}

// waitForServer pings db until it answers or wait runs out. A just-created
// user can be refused briefly by a node that hasn't applied it yet, so
// every error is retried, not only connection errors.
func waitForServer(ctx context.Context, db *sql.DB, wait time.Duration, what string, logf func(string, ...any)) error {
	deadline := time.Now().Add(wait)
	delay := time.Second
	for {
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := db.PingContext(pctx)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !time.Now().Add(delay).Before(deadline) {
			return fmt.Errorf("%s: not reachable within %s: %w", what, wait, err)
		}
		logf("waiting for %s: %v", what, err)
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		delay = min(2*delay, 10*time.Second)
	}
}

// mustConnector can't fail for a config parseDSN accepted: NewConnector
// only re-runs the validation ParseDSN already did. The panic message
// leaves out the error, which could quote the config.
func mustConnector(cfg *mysql.Config) driver.Connector {
	c, err := mysql.NewConnector(cfg)
	if err != nil {
		panic("migrate: a validated database config was refused")
	}
	return c
}
