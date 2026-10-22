package retention

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/objectstore"
)

// LogRetentionCommand is the farmer subcommand of the chart's log
// retention CronJob (logShipping.retention).
const LogRetentionCommand = "log-retention"

// Log retention bounds, in days. 0 (or the flag left out) is the default.
const (
	DefaultLogRetentionDays = 30
	MaxLogRetentionDays     = 3650
)

// Files of the credential directory the CronJob mounts.
const (
	AccessKeyIDFile     = "access-key-id"
	SecretAccessKeyFile = "secret-access-key"
)

// LogRetentionConfig is what LogRetention runs with.
type LogRetentionConfig struct {
	Endpoint string
	UseSSL   bool
	Bucket   string
	// Prefix is the log key root, ending in "/" (logShipping.prefix).
	Prefix string
	// Days is the retention; 0 is DefaultLogRetentionDays.
	Days int
	// CredentialsDir holds access-key-id and secret-access-key: the
	// retention credential, list and delete under Prefix only.
	CredentialsDir string
	// ConnectTimeout bounds how long the endpoint may refuse connections
	// before the run gives up; 0 is DefaultConnectTimeout.
	ConnectTimeout time.Duration
}

// DefaultConnectTimeout rides out an object store restart, but not an
// outage: the S3 client's own retries would hold a Job on a refused
// connection until its deadline (UAT D1 on Azure: three pods, ten minutes,
// and no message saying why).
const DefaultConnectTimeout = time.Minute

// errLogUsage marks a configuration error: exit code 2.
var errLogUsage = errors.New("configuration error")

// LogRetentionDays validates a log retention in days: 0 is the default
// (never "delete at once"), otherwise 1 to MaxLogRetentionDays.
func LogRetentionDays(days int) (int, error) {
	if days == 0 {
		return DefaultLogRetentionDays, nil
	}
	if days < 1 || days > MaxLogRetentionDays {
		return 0, fmt.Errorf("%w: -days %d: want 0 (the default, %d) or 1 to %d", errLogUsage, days, DefaultLogRetentionDays, MaxLogRetentionDays)
	}
	return days, nil
}

// RunLogRetention parses args (everything after the subcommand name),
// deletes the log objects older than the retention once, and returns the
// exit code: 0 on success, 1 on failure, 2 for a usage or configuration
// error.
func RunLogRetention(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("farmer "+LogRetentionCommand, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg LogRetentionConfig
	fs.StringVar(&cfg.Endpoint, "endpoint", "", "the log bucket's S3 endpoint, host:port")
	fs.BoolVar(&cfg.UseSSL, "use-ssl", false, "dial the endpoint with https")
	fs.StringVar(&cfg.Bucket, "bucket", "", "the log bucket")
	fs.StringVar(&cfg.Prefix, "prefix", "logs/", "the log key root, ending in /")
	fs.IntVar(&cfg.Days, "days", 0, fmt.Sprintf("retention in days; 0 is the default (%d), at most %d", DefaultLogRetentionDays, MaxLogRetentionDays))
	fs.StringVar(&cfg.CredentialsDir, "credentials-dir", "", "directory holding the retention credential's "+AccessKeyIDFile+" and "+SecretAccessKeyFile)
	timeout := fs.Duration("timeout", 30*time.Minute, "overall deadline")
	fs.DurationVar(&cfg.ConnectTimeout, "connect-timeout", DefaultConnectTimeout, "give up when the endpoint refuses connections this long")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: farmer %s -endpoint HOST:PORT -bucket NAME -credentials-dir DIR [flags]\n\n", LogRetentionCommand)
		fmt.Fprintf(stderr, "Deletes the log objects whose day is older than the retention.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || cfg.Endpoint == "" || cfg.Bucket == "" || cfg.CredentialsDir == "" {
		fs.Usage()
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	r, err := LogRetention(ctx, cfg, time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", LogRetentionCommand, err)
		if errors.Is(err, errLogUsage) {
			return 2
		}
		return 1
	}
	fmt.Fprintf(stderr, "%s: deleted %d log objects, kept %d, %d with no day in their key left alone\n",
		LogRetentionCommand, r.Deleted, r.Kept, r.Undated)
	return 0
}

// LogRetention deletes the objects of cfg.Bucket under cfg.Prefix whose
// day is before Cutoff(now, days).
func LogRetention(ctx context.Context, cfg LogRetentionConfig, now time.Time) (Result, error) {
	days, err := LogRetentionDays(cfg.Days)
	if err != nil {
		return Result{}, err
	}
	if cfg.Prefix == "" || !strings.HasSuffix(cfg.Prefix, "/") || strings.HasPrefix(cfg.Prefix, "/") {
		return Result{}, fmt.Errorf("%w: -prefix %q: want a key root such as logs/ (ending in /, not starting with one)", errLogUsage, cfg.Prefix)
	}
	id, secret, err := readCredentialDir(cfg.CredentialsDir)
	if err != nil {
		return Result{}, err
	}
	s, err := objectstore.Open(objectstore.Config{
		Endpoint: cfg.Endpoint, UseSSL: cfg.UseSSL, Bucket: cfg.Bucket,
		AccessKeyID: id, SecretAccessKey: secret,
	})
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", errLogUsage, err)
	}
	connectTimeout := cfg.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = DefaultConnectTimeout
	}
	if err := waitReachable(ctx, cfg.Endpoint, connectTimeout); err != nil {
		return Result{}, err
	}
	return SweepDated(ctx, s, cfg.Prefix, LogDate(cfg.Prefix), Cutoff(now, days))
}

// reachRetry is how long waitReachable waits between attempts.
var reachRetry = 2 * time.Second

// waitReachable dials endpoint until a TCP connection opens, for at most
// limit, and otherwise fails with an error that says where to look.
func waitReachable(ctx context.Context, endpoint string, limit time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	var d net.Dialer
	for {
		dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
		c, err := d.DialContext(dctx, "tcp", endpoint)
		dcancel()
		if err == nil {
			_ = c.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("the object store at %s did not accept a connection for %s: %w "+
				"(is it running and Ready? A Service with no ready endpoint refuses connections)", endpoint, limit, err)
		case <-time.After(reachRetry):
		}
	}
}

// readCredentialDir reads the access key pair from dir, refusing an empty
// or whitespace-carrying value (a trailing newline in a Secret is a
// mistake, not part of the key).
func readCredentialDir(dir string) (id, secret string, err error) {
	read := func(name string) (string, error) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", fmt.Errorf("%w: credential: %w", errLogUsage, err)
		}
		v := string(b)
		if v == "" || strings.ContainsFunc(v, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
			return "", fmt.Errorf("%w: credential: %s is empty or holds whitespace", errLogUsage, name)
		}
		return v, nil
	}
	if id, err = read(AccessKeyIDFile); err != nil {
		return "", "", err
	}
	if secret, err = read(SecretAccessKeyFile); err != nil {
		return "", "", err
	}
	return id, secret, nil
}
