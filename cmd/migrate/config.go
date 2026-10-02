package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/yogzblr/imas/internal/migrations"
)

// Environment variables. Each secret one also has a *_FILE form naming a
// file to read it from (a mounted Kubernetes Secret), and a --*-file flag
// doing the same. A secret is never a flag value itself.
const (
	EnvFarmerDSN    = "IMAS_MIGRATE_FARMER_DSN"
	EnvSaasDSN      = "IMAS_MIGRATE_SAAS_DSN"
	EnvRootPassword = "IMAS_MIGRATE_ROOT_PASSWORD"
	EnvRootUser     = "IMAS_MIGRATE_ROOT_USER"
)

type commonConfig struct {
	farmer, saas *mysql.Config
	wait         time.Duration
}

type checkConfig struct{ commonConfig }

type upConfig struct {
	commonConfig
	rootUser     string
	rootPassword string
	skipRoot     bool
	lock         migrations.LockOptions
}

func (c upConfig) accounts() migrations.Accounts {
	return migrations.Accounts{
		Farmer: migrations.Account{Schema: c.farmer.DBName, User: c.farmer.User, Password: c.farmer.Passwd},
		Saas:   migrations.Account{Schema: c.saas.DBName, User: c.saas.User, Password: c.saas.Passwd},
	}
}

// commonFlags are the flags both commands take; resolve reads them once
// the flag set is parsed.
type commonFlags struct {
	farmerFile, saasFile *string
	wait                 *time.Duration
}

func addCommonFlags(fs *flag.FlagSet) commonFlags {
	return commonFlags{
		farmerFile: fs.String("farmer-dsn-file", "", "file holding farmer's DSN (instead of "+EnvFarmerDSN+")"),
		saasFile:   fs.String("saas-dsn-file", "", "file holding saasapi's DSN (instead of "+EnvSaasDSN+")"),
		wait:       fs.Duration("wait", 10*time.Minute, "how long to wait for PXC to accept connections"),
	}
}

func (f commonFlags) resolve(getenv func(string) string) (commonConfig, error) {
	var c commonConfig
	var err error
	if c.farmer, err = loadDSN(EnvFarmerDSN, *f.farmerFile, getenv); err != nil {
		return c, err
	}
	if c.saas, err = loadDSN(EnvSaasDSN, *f.saasFile, getenv); err != nil {
		return c, err
	}
	if *f.wait <= 0 {
		return c, errors.New("--wait must be positive")
	}
	c.wait = *f.wait
	return c, nil
}

func parseCheck(args []string, getenv func(string) string, stderr io.Writer) (checkConfig, error) {
	fs := flag.NewFlagSet("migrate check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	common := addCommonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return checkConfig{}, err
	}
	if fs.NArg() > 0 {
		return checkConfig{}, fmt.Errorf("check takes no arguments, got %q", fs.Args())
	}
	c, err := common.resolve(getenv)
	return checkConfig{c}, err
}

func parseUp(args []string, getenv func(string) string, stderr io.Writer) (upConfig, error) {
	fs := flag.NewFlagSet("migrate up", flag.ContinueOnError)
	fs.SetOutput(stderr)
	common := addCommonFlags(fs)
	rootFile := fs.String("root-password-file", "", "file holding PXC root's password (instead of "+EnvRootPassword+")")
	skipRoot := fs.Bool("skip-root", false, "skip the root step and the enrollment_keys column grant: the schemas, users and grants already exist")
	lease := fs.Duration("lock-lease", 30*time.Minute, "how long the migration lock outlives a stalled run; keep it above the longest DDL statement")
	lockWait := fs.Duration("lock-wait", 15*time.Minute, "how long to wait for another run's migration lock")
	if err := fs.Parse(args); err != nil {
		return upConfig{}, err
	}
	if fs.NArg() > 0 {
		return upConfig{}, fmt.Errorf("up takes no arguments, got %q", fs.Args())
	}
	resolved, err := common.resolve(getenv)
	if err != nil {
		return upConfig{}, err
	}
	if *lease <= 0 || *lockWait <= 0 {
		return upConfig{}, errors.New("--lock-lease and --lock-wait must be positive")
	}
	c := upConfig{
		commonConfig: resolved,
		skipRoot:     *skipRoot,
		lock:         migrations.LockOptions{Lease: *lease, Wait: *lockWait},
	}
	if err := c.accounts().Validate(); err != nil {
		return upConfig{}, err
	}
	// The root step runs once, against farmer's server; saas has to be on
	// the same one or its schema and user would never be created.
	if c.farmer.Net != c.saas.Net || c.farmer.Addr != c.saas.Addr {
		return upConfig{}, errors.New("farmer's and saasapi's DSNs must name the same server")
	}
	if c.skipRoot { // the root password isn't read at all
		return c, nil
	}
	if c.rootPassword, err = loadSecret(EnvRootPassword, *rootFile, getenv); err != nil {
		return upConfig{}, err
	}
	if c.rootPassword == "" {
		return upConfig{}, fmt.Errorf("%s is empty", EnvRootPassword)
	}
	c.rootUser = getenv(EnvRootUser)
	if c.rootUser == "" {
		c.rootUser = "root"
	}
	return c, nil
}

// loadSecret reads env's secret from exactly one of: flagFile, the file
// env_FILE names, or env itself. A trailing newline (as `echo` and most
// editors leave) is dropped; nothing else is.
func loadSecret(env, flagFile string, getenv func(string) string) (string, error) {
	sources := 0
	for _, v := range []string{flagFile, getenv(env + "_FILE"), getenv(env)} {
		if v != "" {
			sources++
		}
	}
	switch {
	case sources == 0:
		return "", fmt.Errorf("%s is not set (or %s_FILE, or its --*-file flag)", env, env)
	case sources > 1:
		return "", fmt.Errorf("%s is set more than one way (%s, %s_FILE, --*-file): set one", env, env, env)
	}
	file := flagFile
	if file == "" {
		file = getenv(env + "_FILE")
	}
	if file == "" {
		return getenv(env), nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("%s: %w", env, err)
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"), nil
}

// loadDSN loads and parses env's DSN. A parse error is reported without
// the driver's message, which can quote the DSN.
func loadDSN(env, flagFile string, getenv func(string) string) (*mysql.Config, error) {
	dsn, err := loadSecret(env, flagFile, getenv)
	if err != nil {
		return nil, err
	}
	cfg, err := mysql.ParseDSN(strings.TrimSpace(dsn))
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid DSN (user:password@tcp(host:port)/schema?params)", env)
	}
	if cfg.User == "" || cfg.DBName == "" {
		return nil, fmt.Errorf("%s must name a user and a schema", env)
	}
	return cfg, nil
}
