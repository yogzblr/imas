package migrations

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

func testAccounts() Accounts {
	return Accounts{
		Farmer: Account{Schema: "farmer", User: "farmer_svc", Password: "f'pw\\x"},
		Saas:   Account{Schema: "saas", User: "saas_svc", Password: "s-pw"},
	}
}

func TestAccountsValidate(t *testing.T) {
	if err := testAccounts().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Accounts){
		"quote in schema":     func(a *Accounts) { a.Farmer.Schema = "farmer`; DROP DATABASE x; --" },
		"quote in user":       func(a *Accounts) { a.Saas.User = "saas'@'%" },
		"empty user":          func(a *Accounts) { a.Saas.User = "" },
		"long user":           func(a *Accounts) { a.Farmer.User = strings.Repeat("u", 33) },
		"hyphen":              func(a *Accounts) { a.Farmer.Schema = "farmer-db" },
		"one user, two roles": func(a *Accounts) { a.Saas.User = a.Farmer.User },
		"one schema":          func(a *Accounts) { a.Saas.Schema = a.Farmer.Schema },
		"root":                func(a *Accounts) { a.Farmer.User = "root" },
	} {
		a := testAccounts()
		mutate(&a)
		if err := a.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestBootstrapStatements pins the grants to §4.1 exactly, and keeps
// passwords out of the SQL text.
func TestBootstrapStatements(t *testing.T) {
	a := testAccounts()
	var grants []string
	for _, st := range a.bootstrapStatements() {
		for _, pw := range []string{a.Farmer.Password, a.Saas.Password} {
			if strings.Contains(st.sql, pw) {
				t.Fatalf("password in SQL text: %s", st.sql)
			}
		}
		if len(st.args) > 0 != st.secret {
			t.Fatalf("%s: args %v but secret=%v", st.sql, st.args, st.secret)
		}
		if strings.HasPrefix(st.sql, "GRANT") {
			grants = append(grants, st.sql)
		}
	}
	want := []string{
		"GRANT ALL ON `farmer`.* TO 'farmer_svc'@'%'",
		"GRANT SELECT ON `saas`.* TO 'farmer_svc'@'%'",
		"GRANT ALL ON `saas`.* TO 'saas_svc'@'%'",
		"GRANT SELECT ON `farmer`.* TO 'saas_svc'@'%'",
	}
	if fmt.Sprint(grants) != fmt.Sprint(want) {
		t.Fatalf("grants\n %q\nwant\n %q", grants, want)
	}
	if got, want := a.enrollmentKeyGrant().sql, "GRANT UPDATE (`used_count`, `last_used_at`) ON `saas`.`enrollment_keys` TO 'farmer_svc'@'%'"; got != want {
		t.Fatalf("column grant %q, want %q", got, want)
	}
}

func TestRedactDropsServerMessage(t *testing.T) {
	err := redact(&mysql.MySQLError{Number: 1064, SQLState: [5]byte{'4', '2', '0', '0', '0'},
		Message: "You have an error in your SQL syntax near 'hunter2'"})
	if strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "1064") {
		t.Fatalf("redacted to %q", err)
	}
	other := errors.New("dial tcp: connection refused")
	if redact(other) != other {
		t.Fatal("a non-server error was changed")
	}
}

func TestRootConfig(t *testing.T) {
	owner, err := mysql.ParseDSN("farmer_svc:pw@tcp(pxc:3306)/farmer?parseTime=true&tls=skip-verify")
	if err != nil {
		t.Fatal(err)
	}
	root := RootConfig(owner, "root", "rootpw")
	if root.User != "root" || root.Passwd != "rootpw" || root.DBName != "" || !root.InterpolateParams {
		t.Fatalf("root config %+v", root)
	}
	if root.Addr != owner.Addr || root.TLSConfig != owner.TLSConfig || !root.ParseTime {
		t.Fatal("root config doesn't keep the owner's server, TLS and parameters")
	}
	if owner.User != "farmer_svc" || owner.DBName != "farmer" || owner.InterpolateParams {
		t.Fatal("RootConfig changed its argument")
	}
}
