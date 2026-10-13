// Package versitysetup implements the two farmer subcommands that set up
// the optional Versity Gateway of the farmer Helm chart (design D18,
// docs/briefs/H-azure-next-runs.md H3): the S3 front of the production
// object store, Azure Blob.
//
//   - versity-iam (RunIAM) is the init container of every gateway pod. It
//     writes the gateway's internal IAM file (users.json) from the
//     per-component credentials the chart mounts from their Secrets, so
//     no S3 user is ever created through the gateway's admin API and
//     every replica serves the same, read-only set of users.
//   - versity-buckets (RunBuckets) is the chart's createBuckets hook Job.
//     It creates the buckets (Azure Blob containers) with the gateway's
//     root credential and gives each its bucket policy, which names the
//     users by access key ID and scopes each to its own buckets and
//     prefixes (design D22).
//
// Users are read from a directory with one subdirectory per user, named
// after it, holding the files access-key-id and (for versity-iam)
// secret-access-key: the layout of the chart's projected Secret volume.
//
// cmd/farmer dispatches here before loading any config, as it does the
// other hook commands (cmd/farmer/subcommands.go).
//
// FLAG FOR SECURITY REVIEW: these commands hold every object store
// credential (versity-iam) and the gateway's root credential
// (versity-buckets), and the policies they write are the only thing that
// keeps one component's credential out of another's buckets.
package versitysetup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Files of a credential directory (one user, or the root).
const (
	AccessKeyIDFile     = "access-key-id"
	SecretAccessKeyFile = "secret-access-key"
)

// errUsage marks a configuration error: exit code 2.
var errUsage = errors.New("configuration error")

// userNameMatcher is a user's directory name: the chart's fixed names
// (farmer, accounts-writer, accounts-reader, saasapi-recipes).
var userNameMatcher = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// accessKeyMatcher is an access key ID the gateway can take: SigV4 puts it
// in the Credential scope, which "/" separates, and in a header, so only
// a conservative set of characters, 3 to 128 of them.
var accessKeyMatcher = regexp.MustCompile(`^[A-Za-z0-9._~+=-]{3,128}$`)

// Credential is one S3 credential read from a directory.
type Credential struct {
	// User is the directory name (the chart's user name); empty for the
	// root credential.
	User   string
	Access string
	// Secret is empty when only the access key ID was read.
	Secret string
}

// readCredential reads dir's access key ID and, with withSecret, its
// secret key. Neither may hold whitespace, a trailing newline included:
// the clients sign with the same Secret's bytes, so trimming here would
// only hide a credential no client can use.
func readCredential(dir, user string, withSecret bool) (Credential, error) {
	c := Credential{User: user}
	name := user
	if name == "" {
		name = "root"
	}
	b, err := os.ReadFile(filepath.Join(dir, AccessKeyIDFile))
	if err != nil {
		return c, fmt.Errorf("%w: %s credential: %w", errUsage, name, err)
	}
	c.Access = string(b)
	if !accessKeyMatcher.MatchString(c.Access) {
		return c, fmt.Errorf("%w: %s credential: the access key ID must be 3 to 128 characters of A-Z a-z 0-9 . _ ~ + = - (no whitespace or newline)", errUsage, name)
	}
	if !withSecret {
		return c, nil
	}
	b, err = os.ReadFile(filepath.Join(dir, SecretAccessKeyFile))
	if err != nil {
		return c, fmt.Errorf("%w: %s credential: %w", errUsage, name, err)
	}
	c.Secret = string(b)
	if len(c.Secret) < 8 || len(c.Secret) > 128 || strings.ContainsFunc(c.Secret, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return c, fmt.Errorf("%w: %s credential: the secret key must be 8 to 128 printable characters with no whitespace or newline", errUsage, name)
	}
	return c, nil
}

// readUsers reads every user under dir, sorted by name. There must be at
// least one, each access key ID must be its own and none may be the
// root's: the gateway would answer as root for it.
func readUsers(dir, rootAccess string, withSecret bool) ([]Credential, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: users directory: %w", errUsage, err)
	}
	var users []Credential
	seen := map[string]string{}
	for _, e := range entries {
		// A projected volume also holds ..data and ..<timestamp> links.
		if strings.HasPrefix(e.Name(), "..") {
			continue
		}
		if !userNameMatcher.MatchString(e.Name()) {
			return nil, fmt.Errorf("%w: users directory: %q is not a user name", errUsage, e.Name())
		}
		c, err := readCredential(filepath.Join(dir, e.Name()), e.Name(), withSecret)
		if err != nil {
			return nil, err
		}
		if c.Access == rootAccess {
			return nil, fmt.Errorf("%w: user %s has the root access key ID", errUsage, c.User)
		}
		if other, dup := seen[c.Access]; dup {
			return nil, fmt.Errorf("%w: users %s and %s have the same access key ID; every component needs a credential of its own", errUsage, other, c.User)
		}
		seen[c.Access] = c.User
		users = append(users, c)
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("%w: users directory %s holds no user", errUsage, dir)
	}
	slices.SortFunc(users, func(a, b Credential) int { return strings.Compare(a.User, b.User) })
	return users, nil
}
