package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"

	"github.com/go-sql-driver/mysql"
)

// Account is one schema and the user that owns it.
type Account struct {
	Schema   string
	User     string
	Password string
}

// Accounts are the two schema owners the root step sets up.
type Accounts struct {
	Farmer Account
	Saas   Account
}

// identRE is what a schema or user name may be: it's written into DDL,
// which takes no placeholders for identifiers. The same rule as the Helm
// chart's (deploy/helm/farmer/templates/db-bootstrap-job.yaml); 32 is
// MySQL's user name limit.
var identRE = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)

// Validate refuses names that can't be written into DDL safely, and any
// overlap between the two accounts: one user owning both schemas, or both
// accounts naming one schema, would undo single writer per schema.
func (a Accounts) Validate() error {
	for _, v := range []struct{ what, name string }{
		{"farmer schema", a.Farmer.Schema}, {"farmer user", a.Farmer.User},
		{"saas schema", a.Saas.Schema}, {"saas user", a.Saas.User},
	} {
		if !identRE.MatchString(v.name) {
			return fmt.Errorf("%s name %q must match %s", v.what, v.name, identRE)
		}
	}
	if a.Farmer.Schema == a.Saas.Schema {
		return fmt.Errorf("farmer and saas must be different schemas, both are %q", a.Farmer.Schema)
	}
	if a.Farmer.User == a.Saas.User {
		return fmt.Errorf("farmer and saas must be different users, both are %q", a.Farmer.User)
	}
	for _, u := range []string{a.Farmer.User, a.Saas.User} {
		if u == "root" || u == "mysql.sys" || u == "mysql.session" || u == "mysql.infoschema" {
			return fmt.Errorf("refusing to manage the built-in user %q", u)
		}
	}
	return nil
}

// statement is one root-step statement. A password goes in args, never
// in sql, so neither the SQL text nor an error built from it carries it.
type statement struct {
	sql  string
	args []any
	// secret marks a statement whose args are a password. Its error is
	// reduced to the MySQL error number, since a server error message can
	// quote the statement it got, password literal included.
	secret bool
}

func (a Accounts) bootstrapStatements() []statement {
	f, s := a.Farmer, a.Saas
	var out []statement
	for _, schema := range []string{f.Schema, s.Schema} {
		out = append(out, statement{sql: "CREATE DATABASE IF NOT EXISTS `" + schema + "` DEFAULT CHARACTER SET utf8mb4"})
	}
	for _, acct := range []Account{f, s} {
		// ALTER as well as CREATE: CREATE IF NOT EXISTS leaves an existing
		// user's password alone, and the password in the secret is the one
		// the services use.
		out = append(out,
			statement{sql: "CREATE USER IF NOT EXISTS " + userSpec(acct.User) + " IDENTIFIED BY ?", args: []any{acct.Password}, secret: true},
			statement{sql: "ALTER USER " + userSpec(acct.User) + " IDENTIFIED BY ?", args: []any{acct.Password}, secret: true},
		)
	}
	// §4.1: each user writes its own schema and only reads the other's.
	out = append(out,
		statement{sql: "GRANT ALL ON `" + f.Schema + "`.* TO " + userSpec(f.User)},
		statement{sql: "GRANT SELECT ON `" + s.Schema + "`.* TO " + userSpec(f.User)},
		statement{sql: "GRANT ALL ON `" + s.Schema + "`.* TO " + userSpec(s.User)},
		statement{sql: "GRANT SELECT ON `" + f.Schema + "`.* TO " + userSpec(s.User)},
	)
	return out
}

// enrollmentKeyGrant is the one exception to single writer (§3.3, §4.1):
// farmer redeems enrollment keys by incrementing their use count. It
// needs the table, so it runs after the saas migrations.
func (a Accounts) enrollmentKeyGrant() statement {
	return statement{sql: "GRANT UPDATE (`used_count`, `last_used_at`) ON `" + a.Saas.Schema + "`.`enrollment_keys` TO " + userSpec(a.Farmer.User)}
}

// userSpec is 'user'@'%'. Every account is '%': the pods' addresses
// aren't fixed.
func userSpec(user string) string { return "'" + user + "'@'%'" }

// Bootstrap is the root step's first half, as PXC's root: creates both
// schemas and both users if they're missing, sets each user's password,
// and applies §4.1's schema-level grants. Every statement is idempotent,
// so it's safe to re-run and to run concurrently. root must be opened
// with interpolateParams=true (see RootConfig): the password is a
// placeholder, and MySQL can't prepare CREATE USER ... IDENTIFIED BY ?.
//
// It only adds: privileges granted by hand beyond §4.1 are left alone.
func Bootstrap(ctx context.Context, root *sql.DB, a Accounts) error {
	if err := a.Validate(); err != nil {
		return err
	}
	return execAll(ctx, root, a.bootstrapStatements())
}

// GrantEnrollmentKeyColumns is the root step's second half, run after
// both migration sets: farmer's column grant on saas.enrollment_keys.
func GrantEnrollmentKeyColumns(ctx context.Context, root *sql.DB, a Accounts) error {
	if err := a.Validate(); err != nil {
		return err
	}
	return execAll(ctx, root, []statement{a.enrollmentKeyGrant()})
}

func execAll(ctx context.Context, db *sql.DB, stmts []statement) error {
	for _, st := range stmts {
		if _, err := db.ExecContext(ctx, st.sql, st.args...); err != nil {
			if st.secret {
				return fmt.Errorf("%s: %w", st.sql, redact(err))
			}
			return fmt.Errorf("%s: %w", st.sql, err)
		}
	}
	return nil
}

// redact keeps a MySQL error's number and SQLSTATE and drops its
// message. Anything else (a network error, a cancelled context) has no
// statement text in it and passes through.
func redact(err error) error {
	var me *mysql.MySQLError
	if errors.As(err, &me) {
		return fmt.Errorf("MySQL error %d (%s), message withheld: the statement carries a password", me.Number, string(me.SQLState[:]))
	}
	return err
}

// RootConfig derives the root connection from an owner's DSN config:
// same server, TLS and parameters, root's credentials, no default
// schema, and interpolateParams on (see Bootstrap). cfg isn't modified.
func RootConfig(cfg *mysql.Config, user, password string) *mysql.Config {
	root := cfg.Clone()
	root.User = user
	root.Passwd = password
	root.DBName = ""
	root.InterpolateParams = true
	return root
}
