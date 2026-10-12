package main

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/config"
)

// The accounts bucket must be its own bucket with its own credential.
func TestCheckAccountStore(t *testing.T) {
	oldBucket, oldJob, oldKey := config.S3Bucket, config.S3JobBucket, config.S3AccessKeyID
	t.Cleanup(func() { config.S3Bucket, config.S3JobBucket, config.S3AccessKeyID = oldBucket, oldJob, oldKey })
	config.S3Bucket, config.S3JobBucket, config.S3AccessKeyID = "recipes", "jobs", "farmer"

	good := config.AccountStoreConfig{Endpoint: "s3:9000", Bucket: "imas-accounts", AccessKeyID: "accounts-writer", SecretAccessKey: "x"}
	if err := checkAccountStore(good, "sprout-jwts"); err != nil {
		t.Fatalf("own bucket and credential: %v", err)
	}
	for _, c := range []struct {
		name   string
		mutate func(*config.AccountStoreConfig)
		sprout string
		want   string
	}{
		{"no bucket", func(a *config.AccountStoreConfig) { a.Bucket = "" }, "", "no accounts bucket"},
		{"no endpoint", func(a *config.AccountStoreConfig) { a.Endpoint = "" }, "", "no endpoint"},
		{"no credential", func(a *config.AccountStoreConfig) { a.SecretAccessKey = "" }, "", "no write credential"},
		{"farmer's credential", func(a *config.AccountStoreConfig) { a.AccessKeyID = "farmer" }, "", "must not be farmer's"},
		{"recipe bucket", func(a *config.AccountStoreConfig) { a.Bucket = "recipes" }, "", "must be its own"},
		{"job bucket", func(a *config.AccountStoreConfig) { a.Bucket = "jobs" }, "", "must be its own"},
		{"sprout JWT bucket", func(a *config.AccountStoreConfig) { a.Bucket = "sprout-jwts" }, "sprout-jwts", "must be its own"},
	} {
		t.Run(c.name, func(t *testing.T) {
			acc := good
			c.mutate(&acc)
			if err := checkAccountStore(acc, c.sprout); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

// Farmer refuses to start without the accounts bucket (E6 item 3): no
// silent fallback to pushing the bus alone. initAccountPublisher exits
// non-zero naming the variable; run in a child process, as it exits.
func TestInitAccountPublisherRefusesWithoutBucket(t *testing.T) {
	if os.Getenv("IMAS_TEST_INIT_ACCOUNT_PUBLISHER") == "1" {
		config.AccountStore = config.AccountStoreConfig{}
		initAccountPublisher()
		return // not reached: initAccountPublisher must exit
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestInitAccountPublisherRefusesWithoutBucket$")
	cmd.Env = append(os.Environ(), "IMAS_TEST_INIT_ACCOUNT_PUBLISHER=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() == 0 {
		t.Fatalf("farmer started without an accounts bucket (err %v):\n%s", err, out)
	}
	if !strings.Contains(string(out), "no accounts bucket") || !strings.Contains(string(out), config.EnvAccountsS3Bucket) {
		t.Fatalf("exit without the reason:\n%s", out)
	}
}
