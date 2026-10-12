package main

import (
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
