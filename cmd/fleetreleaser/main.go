// Command fleetreleaser is the only process that signs sprout releases.
// CloudXP's release pipeline runs it once per release package with the
// version, OS, arch, file name, SHA-256 and minimum sprout version; it
// signs that fleetsign.Manifest's canonical string
// version|os|arch|file_name|checksum_sha256|min_sprout_version with the
// OpenBao Transit key imas-fleet-signing (Ed25519) and writes the row,
// signature and (unsigned) artifact URL included, straight into
// saas.fleet_versions over its own database credential. See
// docs/design/cloudxp-machine-manager-api-design.md §2.5. FU.34 turns it
// into a stateless signing service with no database access.
//
// Why a separate binary rather than a saasapi endpoint or a library:
// saasapi already has write access to saas.fleet_versions. If the same
// process could also sign, anyone who got code execution in saasapi (or
// its credentials) could mint a release every sprout would install. Here
// the two powers sit with different identities: saasapi and farmer get
// read-only Transit access to the key (verify, read public key), and
// this binary gets sign. The SaaS API's request path is never in the
// signing loop.
//
// FLAG FOR SECURITY REVIEW — the split is only as good as the OpenBao
// policies in deploy/fleetreleaser/.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/yogzblr/imas/internal/fleetsign"
)

// EnvDSN is fleetreleaser's own GORM MySQL DSN for the saas schema. It
// is a dedicated database user (SELECT, INSERT and UPDATE(signature) on
// saas.fleet_versions only; see deploy/fleetreleaser/README.md), never
// saasapi's saas_svc.
const EnvDSN = "IMAS_FLEETRELEASER_DSN"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run returns the process exit code: 0 when the release is in
// saas.fleet_versions, signed (inserted, backfilled, or already there);
// 1 when signing or writing failed; 2 for a usage or configuration error.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fleetreleaser", flag.ContinueOnError)
	fs.SetOutput(stderr)
	version := fs.String("version", "", "sprout release version, e.g. v2.4.1 (required)")
	osName := fs.String("os", "", "package OS, e.g. linux (required)")
	arch := fs.String("arch", "", "package architecture, e.g. amd64 (required)")
	fileName := fs.String("file-name", "", "package file name in the sprout repository (required)")
	minSproutVersion := fs.String("min-sprout-version", "", "oldest sprout version that may update to this release, e.g. v2.0.0 (required)")
	artifactURL := fs.String("artifact-url", "", "https URL the release binary was published to, stored unsigned (required)")
	checksum := fs.String("checksum-sha256", "", "hex SHA-256 of the release binary (required)")
	notes := fs.String("notes", "", "release notes for GET /versions")
	releasedAtStr := fs.String("released-at", "", "RFC 3339 release time (default now)")
	timeout := fs.Duration("timeout", 2*time.Minute, "overall deadline")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: fleetreleaser -version V -os OS -arch ARCH -file-name NAME -min-sprout-version V -artifact-url URL -checksum-sha256 HEX [flags]\n\n")
		fmt.Fprintf(stderr, "Signs a sprout release with OpenBao Transit key %q and writes it to saas.fleet_versions.\n",
			fleetsign.DefaultTransitKeyName)
		fmt.Fprintf(stderr, "Database: %s. OpenBao: %s, %s, %s, ...\n\n", EnvDSN, EnvOpenBaoAddr, EnvOpenBaoAuthMethod, EnvOpenBaoK8sRole)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		return 2
	}

	rel := release{
		Manifest: fleetsign.Manifest{
			Version:          strings.TrimSpace(*version),
			OS:               strings.TrimSpace(*osName),
			Arch:             strings.TrimSpace(*arch),
			FileName:         strings.TrimSpace(*fileName),
			ChecksumSHA256:   strings.ToLower(strings.TrimSpace(*checksum)),
			MinSproutVersion: strings.TrimSpace(*minSproutVersion),
		},
		ArtifactURL: strings.TrimSpace(*artifactURL),
	}
	if err := rel.validate(); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	releasedAt := time.Now()
	if *releasedAtStr != "" {
		t, err := time.Parse(time.RFC3339, *releasedAtStr)
		if err != nil {
			fmt.Fprintf(stderr, "-released-at: %v\n", err)
			return 2
		}
		releasedAt = t
	}

	signer, err := newTransitClientFromEnv()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	dsn := os.Getenv(EnvDSN)
	if dsn == "" {
		fmt.Fprintf(stderr, "%s is required\n", EnvDSN)
		return 2
	}
	// No AutoMigrate: saasapi owns the saas schema. If the signature
	// column isn't there yet, the insert fails and nothing is written.
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Warn)})
	if err != nil {
		fmt.Fprintf(stderr, "fleetreleaser: opening saas schema: %v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	out, err := publish(ctx, db, signer, rel, *notes, releasedAt)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "fleetreleaser: %s %s (key %s)\n", rel.Version, out, signer.keyName)
	return 0
}
