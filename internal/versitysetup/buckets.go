package versitysetup

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// BucketsCommand is the farmer subcommand of the chart's createBuckets
// hook Job.
const BucketsCommand = "versity-buckets"

// Plan is the bucket plan the chart renders into its ConfigMap: every
// bucket the chart names and the statements of its policy.
type Plan struct {
	Buckets []PlanBucket `json:"buckets"`
}

// PlanBucket is one bucket (an Azure Blob container behind the gateway).
type PlanBucket struct {
	Name       string          `json:"name"`
	Statements []PlanStatement `json:"statements"`
}

// PlanStatement is one Allow statement of a bucket policy. User names a
// user directory; the command puts that user's access key ID in the
// statement's Principal, since the chart never sees access key IDs.
type PlanStatement struct {
	Sid       string          `json:"sid"`
	User      string          `json:"user"`
	Actions   []string        `json:"actions"`
	Resources []string        `json:"resources"`
	Condition json.RawMessage `json:"condition,omitempty"`
}

// containerNameMatcher is a bucket name that is also an Azure Blob
// container name: 3 to 63 lower-case letters, digits and hyphens,
// starting and ending with a letter or digit (and no "--", checked apart).
var containerNameMatcher = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

// actionMatcher is an S3 action the policies may grant: a plain s3:Name,
// never a wildcard.
var actionMatcher = regexp.MustCompile(`^s3:[A-Za-z]+$`)

var sidMatcher = regexp.MustCompile(`^[A-Za-z0-9]{1,64}$`)

// policy is the bucket policy document the gateway stores (versitygw
// auth.BucketPolicy, AWS's format).
type policy struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Sid       string              `json:"Sid"`
	Effect    string              `json:"Effect"`
	Principal map[string][]string `json:"Principal"`
	Action    []string            `json:"Action"`
	Resource  []string            `json:"Resource"`
	Condition json.RawMessage     `json:"Condition,omitempty"`
}

// BucketsConfig is what RunBuckets runs with.
type BucketsConfig struct {
	// Endpoint is the gateway, host:port, no scheme.
	Endpoint string
	UseSSL   bool
	Region   string
	// RootDir holds the gateway root credential (access-key-id and
	// secret-access-key); UsersDir every user's access-key-id.
	RootDir  string
	UsersDir string
	PlanFile string
	// RetryWait is the first wait after a transient failure; it doubles
	// up to 30 times as long. Zero: 2s.
	RetryWait time.Duration
}

// RunBuckets parses args (everything after the subcommand name), creates
// the buckets and writes their policies, and returns the exit code: 0 on
// success, 1 on failure, 2 for a usage or configuration error.
func RunBuckets(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("farmer "+BucketsCommand, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cfg BucketsConfig
	fs.StringVar(&cfg.Endpoint, "endpoint", "", "the gateway's S3 endpoint, host:port")
	fs.BoolVar(&cfg.UseSSL, "use-ssl", false, "dial the endpoint with https")
	fs.StringVar(&cfg.Region, "region", "us-east-1", "the gateway's region (VGW_REGION)")
	fs.StringVar(&cfg.RootDir, "root-dir", "", "directory holding the root credential's "+AccessKeyIDFile+" and "+SecretAccessKeyFile)
	fs.StringVar(&cfg.UsersDir, "users-dir", "", "directory with one subdirectory per user, each holding "+AccessKeyIDFile)
	fs.StringVar(&cfg.PlanFile, "plan", "", "the bucket plan (JSON) the chart renders")
	timeout := fs.Duration("timeout", 10*time.Minute, "overall deadline, retries for an unreachable gateway included")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: farmer %s -endpoint HOST:PORT -root-dir DIR -users-dir DIR -plan FILE [flags]\n\n", BucketsCommand)
		fmt.Fprintf(stderr, "Creates the chart's buckets on the Versity Gateway and writes their bucket policies.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || cfg.Endpoint == "" || cfg.RootDir == "" || cfg.UsersDir == "" || cfg.PlanFile == "" {
		fs.Usage()
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := EnsureBuckets(ctx, cfg, stderr); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", BucketsCommand, err)
		if errors.Is(err, errUsage) {
			return 2
		}
		return 1
	}
	return 0
}

// EnsureBuckets creates every bucket of the plan that is missing and sets
// its policy, then reads each policy back. It is idempotent: a bucket the
// root already owns is kept, and its policy is replaced by the plan's,
// so a removed grant goes too. A bucket someone else owns fails the run.
// Unreachable gateways and 5xx answers are retried until ctx is done;
// any other refusal is final.
func EnsureBuckets(ctx context.Context, cfg BucketsConfig, out io.Writer) error {
	plan, err := ReadPlan(cfg.PlanFile)
	if err != nil {
		return err
	}
	root, err := readCredential(cfg.RootDir, "", true)
	if err != nil {
		return err
	}
	users, err := readUsers(cfg.UsersDir, root.Access, false)
	if err != nil {
		return err
	}
	keys := map[string]string{}
	for _, u := range users {
		keys[u.User] = u.Access
	}
	policies := map[string]string{}
	for _, b := range plan.Buckets {
		p, err := bucketPolicy(b, keys)
		if err != nil {
			return err
		}
		policies[b.Name] = p
	}
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(root.Access, root.Secret, ""),
		Secure:       cfg.UseSSL,
		Region:       cfg.Region,
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		return fmt.Errorf("%w: endpoint %s: %w", errUsage, cfg.Endpoint, err)
	}
	wait := cfg.RetryWait
	if wait <= 0 {
		wait = 2 * time.Second
	}
	for _, b := range plan.Buckets {
		err := retry(ctx, wait, out, "creating bucket "+b.Name, func() error {
			err := client.MakeBucket(ctx, b.Name, minio.MakeBucketOptions{Region: cfg.Region})
			if minio.ToErrorResponse(err).Code == "BucketAlreadyOwnedByYou" {
				return nil
			}
			return err
		})
		if err != nil {
			return err
		}
		// A gateway pod still on the previous user set (a rolling
		// upgrade that adds a user) refuses a principal it doesn't know
		// as a malformed policy; another pod, or the same one once
		// rolled, takes it, so that is retried too.
		if err := retryIf(ctx, wait, out, "writing the policy of "+b.Name, func() error {
			return client.SetBucketPolicy(ctx, b.Name, policies[b.Name])
		}, func(err error) bool { return minio.ToErrorResponse(err).Code == "MalformedPolicy" }); err != nil {
			return err
		}
		var got string
		if err := retry(ctx, wait, out, "reading back the policy of "+b.Name, func() (err error) {
			got, err = client.GetBucketPolicy(ctx, b.Name)
			return err
		}); err != nil {
			return err
		}
		if !sameJSON(got, policies[b.Name]) {
			return fmt.Errorf("bucket %s: the gateway holds a different policy from the one written", b.Name)
		}
		fmt.Fprintf(out, "%s: bucket %s ready, policy with %d statements\n", BucketsCommand, b.Name, len(b.Statements))
	}
	return nil
}

// ReadPlan reads and checks the plan: bucket names valid for S3 and Azure
// Blob and each listed once, at least one statement each, and every
// statement an Allow of plain s3: actions on that bucket alone.
func ReadPlan(file string) (Plan, error) {
	var plan Plan
	b, err := os.ReadFile(file)
	if err != nil {
		return plan, fmt.Errorf("%w: plan: %w", errUsage, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&plan); err != nil {
		return plan, fmt.Errorf("%w: plan: %w", errUsage, err)
	}
	if len(plan.Buckets) == 0 {
		return plan, fmt.Errorf("%w: plan names no bucket", errUsage)
	}
	seen := map[string]bool{}
	for _, bk := range plan.Buckets {
		if !containerNameMatcher.MatchString(bk.Name) || strings.Contains(bk.Name, "--") {
			return plan, fmt.Errorf("%w: plan: %q is not a bucket name Azure Blob takes as a container name (3 to 63 of a-z 0-9 -, no leading, trailing or double hyphen)", errUsage, bk.Name)
		}
		if seen[bk.Name] {
			return plan, fmt.Errorf("%w: plan: bucket %s listed twice", errUsage, bk.Name)
		}
		seen[bk.Name] = true
		if len(bk.Statements) == 0 {
			return plan, fmt.Errorf("%w: plan: bucket %s has no statement; nothing but root could use it", errUsage, bk.Name)
		}
		sids := map[string]bool{}
		for _, s := range bk.Statements {
			if !sidMatcher.MatchString(s.Sid) || sids[s.Sid] {
				return plan, fmt.Errorf("%w: plan: bucket %s: statement id %q is empty, not alphanumeric or repeated", errUsage, bk.Name, s.Sid)
			}
			sids[s.Sid] = true
			if len(s.Actions) == 0 || len(s.Resources) == 0 {
				return plan, fmt.Errorf("%w: plan: bucket %s statement %s needs actions and resources", errUsage, bk.Name, s.Sid)
			}
			for _, a := range s.Actions {
				if !actionMatcher.MatchString(a) {
					return plan, fmt.Errorf("%w: plan: bucket %s statement %s: %q is not a plain s3: action", errUsage, bk.Name, s.Sid, a)
				}
			}
			arn := "arn:aws:s3:::" + bk.Name
			for _, r := range s.Resources {
				if r != arn && !strings.HasPrefix(r, arn+"/") {
					return plan, fmt.Errorf("%w: plan: bucket %s statement %s: resource %q is outside the bucket", errUsage, bk.Name, s.Sid, r)
				}
			}
			if len(s.Condition) > 0 {
				var m map[string]map[string]any
				if err := json.Unmarshal(s.Condition, &m); err != nil {
					return plan, fmt.Errorf("%w: plan: bucket %s statement %s: condition: %w", errUsage, bk.Name, s.Sid, err)
				}
			}
		}
	}
	return plan, nil
}

// bucketPolicy renders b's policy with each statement's user replaced by
// its access key ID.
func bucketPolicy(b PlanBucket, keys map[string]string) (string, error) {
	p := policy{Version: "2012-10-17"}
	for _, s := range b.Statements {
		key, ok := keys[s.User]
		if !ok {
			return "", fmt.Errorf("%w: plan: bucket %s statement %s names user %q, which has no credential in the users directory", errUsage, b.Name, s.Sid, s.User)
		}
		p.Statement = append(p.Statement, policyStatement{
			Sid:       s.Sid,
			Effect:    "Allow",
			Principal: map[string][]string{"AWS": {key}},
			Action:    s.Actions,
			Resource:  s.Resources,
			Condition: s.Condition,
		})
	}
	out, err := json.Marshal(p)
	return string(out), err
}

// retry runs fn until it succeeds, fails for good or ctx is done. Only
// an unreachable gateway, a 5xx or a throttle is retried.
func retry(ctx context.Context, wait time.Duration, out io.Writer, what string, fn func() error) error {
	return retryIf(ctx, wait, out, what, fn, nil)
}

// retryIf is retry that also retries the errors also reports true for.
func retryIf(ctx context.Context, wait time.Duration, out io.Writer, what string, fn func() error, also func(error) bool) error {
	maxWait := 30 * wait
	for attempt := 1; ; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}
		if !transient(err) && (also == nil || !also(err)) {
			return fmt.Errorf("%s: %w", what, err)
		}
		fmt.Fprintf(out, "%s: %s failed (attempt %d), retrying in %s: %v\n", BucketsCommand, what, attempt, wait, err)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return fmt.Errorf("%s: gave up: %w", what, errors.Join(ctx.Err(), err))
		case <-t.C:
		}
		wait = min(2*wait, maxWait)
	}
}

// transient reports whether err can go away by waiting: no S3 answer at
// all (the gateway is still starting), a 5xx, or a throttle.
func transient(err error) bool {
	resp := minio.ToErrorResponse(err)
	switch {
	case resp.StatusCode == 0 && resp.Code == "":
		return true
	case resp.StatusCode >= 500:
		return true
	case resp.Code == "SlowDown" || resp.Code == "ServiceUnavailable" || resp.Code == "InternalError" || resp.StatusCode == 429:
		return true
	}
	return false
}

// sameJSON reports whether a and b are the same JSON value.
func sameJSON(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}
