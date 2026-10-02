package main

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/yogzblr/imas/internal/migrations"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

const (
	farmerDSN = "farmer_svc:farmer-secret@tcp(pxc:3306)/farmer?parseTime=true"
	saasDSN   = "saas_svc:saas-secret@tcp(pxc:3306)/saas?parseTime=true"
)

func TestLoadSecret(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "pw")
	if err := os.WriteFile(file, []byte(" from file \r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		env      map[string]string
		flagFile string
		want     string
		bad      bool
	}{
		{name: "env", env: map[string]string{"X": "from env"}, want: "from env"},
		{name: "env file", env: map[string]string{"X_FILE": file}, want: " from file "},
		{name: "flag file", flagFile: file, want: " from file "},
		{name: "unset", bad: true},
		{name: "env and env file", env: map[string]string{"X": "a", "X_FILE": file}, bad: true},
		{name: "env and flag", env: map[string]string{"X": "a"}, flagFile: file, bad: true},
		{name: "missing file", env: map[string]string{"X_FILE": filepath.Join(dir, "nope")}, bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadSecret("X", tc.flagFile, envOf(tc.env))
			if tc.bad {
				if err == nil {
					t.Fatalf("got %q, want an error", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// TestLoadDSNErrorsQuoteNothing: a malformed DSN's error names the
// variable, never the DSN or the password in it.
func TestLoadDSNErrorsQuoteNothing(t *testing.T) {
	for _, dsn := range []string{
		"farmer_svc:hunter2@tcp(pxc:3306)/farmer?tls=nosuchconfig",
		"farmer_svc:hunter2@tcp(pxc:3306/farmer",
		"farmer_svc:hunter2@tcp(pxc:3306)/",
		":hunter2@tcp(pxc:3306)/farmer",
	} {
		_, err := loadDSN(EnvFarmerDSN, "", envOf(map[string]string{EnvFarmerDSN: dsn}))
		if err == nil {
			t.Fatalf("%q accepted", dsn)
		}
		if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "pxc") {
			t.Fatalf("error quotes the DSN: %v", err)
		}
	}
}

func TestParseUp(t *testing.T) {
	base := map[string]string{EnvFarmerDSN: farmerDSN, EnvSaasDSN: saasDSN, EnvRootPassword: "root-secret"}
	with := func(kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}

	c, err := parseUp(nil, envOf(base), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if c.rootUser != "root" || c.rootPassword != "root-secret" || c.skipRoot {
		t.Fatalf("config %+v", c)
	}
	if a := c.accounts(); a.Farmer != (migrations.Account{Schema: "farmer", User: "farmer_svc", Password: "farmer-secret"}) ||
		a.Saas != (migrations.Account{Schema: "saas", User: "saas_svc", Password: "saas-secret"}) {
		t.Fatalf("accounts %+v", a)
	}
	if c.lock.Lease != 30*time.Minute || c.lock.Wait != 15*time.Minute {
		t.Fatalf("lock options %+v", c.lock)
	}

	if c, err := parseUp(nil, envOf(with(EnvRootUser, "admin")), &bytes.Buffer{}); err != nil || c.rootUser != "admin" {
		t.Fatalf("root user: %q, %v", c.rootUser, err)
	}
	noRoot := with()
	delete(noRoot, EnvRootPassword)
	if c, err := parseUp([]string{"--skip-root"}, envOf(noRoot), &bytes.Buffer{}); err != nil || !c.skipRoot || c.rootPassword != "" {
		t.Fatalf("--skip-root: %+v, %v", c, err)
	}

	for name, tc := range map[string]struct {
		args []string
		env  map[string]string
	}{
		"no root password":    {nil, noRoot},
		"empty root password": {nil, with(EnvRootPassword+"_FILE", "/dev/null", EnvRootPassword, "")},
		"one user":            {nil, with(EnvSaasDSN, "farmer_svc:x@tcp(pxc:3306)/saas")},
		"one schema":          {nil, with(EnvSaasDSN, "saas_svc:x@tcp(pxc:3306)/farmer")},
		"two servers":         {nil, with(EnvSaasDSN, "saas_svc:x@tcp(other:3306)/saas")},
		"bad identifier":      {nil, with(EnvFarmerDSN, "farmer-svc:x@tcp(pxc:3306)/farmer")},
		"no saas DSN":         {nil, with(EnvSaasDSN, "")},
		"argument":            {[]string{"extra"}, base},
		"password as a flag":  {[]string{"--root-password", "x"}, base},
		"negative lease":      {[]string{"--lock-lease", "-1s"}, base},
		"zero wait":           {[]string{"--wait", "0s"}, base},
		"root password twice": {[]string{"--root-password-file", "/dev/null"}, base},
		"farmer DSN two ways": {[]string{"--farmer-dsn-file", "/dev/null"}, base},
		"unparseable DSN":     {nil, with(EnvFarmerDSN, "not a dsn")},
	} {
		if _, err := parseUp(tc.args, envOf(tc.env), &bytes.Buffer{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseCheckNeedsNoRoot(t *testing.T) {
	c, err := parseCheck(nil, envOf(map[string]string{EnvFarmerDSN: farmerDSN, EnvSaasDSN: saasDSN}), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if c.farmer.DBName != "farmer" || c.saas.DBName != "saas" {
		t.Fatalf("config %+v", c)
	}
	if _, err := parseCheck([]string{"--skip-root"}, envOf(map[string]string{EnvFarmerDSN: farmerDSN, EnvSaasDSN: saasDSN}), &bytes.Buffer{}); err == nil {
		t.Fatal("check accepted an up flag")
	}
}

func TestRunUsage(t *testing.T) {
	for args, want := range map[string]int{"": 2, "frobnicate": 2, "help": 0, "up -h": 0, "check -h": 0, "up": 2, "check": 2} {
		var out, errOut bytes.Buffer
		if got := run(context.Background(), strings.Fields(args), envOf(nil), &out, &errOut); got != want {
			t.Errorf("migrate %s: exit %d, want %d (%s)", args, got, want, errOut.String())
		}
	}
}

// End to end against a real server; see internal/migrations/mysql_test.go
// for IMAS_TEST_MYSQL_ROOT_DSN.

func TestMySQLUpThenCheck(t *testing.T) {
	rootDSN := os.Getenv("IMAS_TEST_MYSQL_ROOT_DSN")
	if rootDSN == "" {
		t.Skip("IMAS_TEST_MYSQL_ROOT_DSN not set; skipping the MySQL tests")
	}
	rootCfg, err := mysql.ParseDSN(rootDSN)
	if err != nil {
		t.Fatal("IMAS_TEST_MYSQL_ROOT_DSN: not a valid DSN")
	}
	sfx := fmt.Sprintf("%x", time.Now().UnixNano()&0xffffffff)
	owner := func(name, pw string) string {
		c := rootCfg.Clone()
		c.User, c.Passwd, c.DBName = name+"_"+sfx, pw, name+"_"+sfx
		return c.FormatDSN()
	}
	farmerPW, saasPW := "fpw-'\"\\-"+sfx, "spw-"+sfx
	env := map[string]string{
		EnvFarmerDSN:    owner("t_mf", farmerPW),
		EnvSaasDSN:      owner("t_ms", saasPW),
		EnvRootPassword: rootCfg.Passwd,
		EnvRootUser:     rootCfg.User,
	}
	rc := rootCfg.Clone()
	rc.DBName = ""
	root, err := sql.Open("mysql", rc.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	t.Cleanup(func() {
		for _, n := range []string{"t_mf_" + sfx, "t_ms_" + sfx} {
			root.Exec("DROP DATABASE IF EXISTS `" + n + "`")
			root.Exec("DROP USER IF EXISTS '" + n + "'@'%'")
		}
	})

	var logs bytes.Buffer
	logf := func(format string, args ...any) { fmt.Fprintf(&logs, format+"\n", args...) }
	ctx := context.Background()
	cfg, err := parseUp([]string{"--wait", "30s"}, envOf(env), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := up(ctx, cfg, logf); err != nil {
			t.Fatalf("up: %v\n%s", err, logs.String())
		}
	}
	for _, secret := range []string{farmerPW, saasPW, rootCfg.Passwd, env[EnvFarmerDSN], env[EnvSaasDSN]} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("logs carry a secret or DSN:\n%s", logs.String())
		}
	}

	ccfg, err := parseCheck([]string{"--wait", "30s"}, envOf(env), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := check(ctx, ccfg, &out, logf); err != nil {
		t.Fatalf("check after up: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "farmer: ok") || !strings.Contains(out.String(), "saas: ok") {
		t.Fatalf("check output:\n%s", out.String())
	}

	// A newer binary's contract migration raises saas's floor past this
	// binary: check must now fail, as a helm rollback to it should.
	if _, err := root.Exec("UPDATE `t_ms_"+sfx+"`.`"+migrations.InfoTable+"` SET min_compatible_version = ?", migrations.Saas.Latest()+1); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := check(ctx, ccfg, &out, logf); err == nil {
		t.Fatalf("check passed a schema whose floor excludes this binary:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "saas: NOT SUPPORTED") || !strings.Contains(out.String(), "farmer: ok") {
		t.Fatalf("check output:\n%s", out.String())
	}
	if err := up(ctx, cfg, logf); err == nil {
		t.Fatal("up ran against a schema too new for it")
	}
}
