package versitysetup

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// IAMCommand is the farmer subcommand of the gateway pods' init container.
const IAMCommand = "versity-iam"

// IAMFile is the file name the gateway's internal IAM reads in its IAM
// directory (VGW_IAM_DIR; versitygw auth/iam_internal.go).
const IAMFile = "users.json"

// iamAccount is one entry of the gateway's internal IAM file, in its own
// JSON shape (versitygw auth.Account). Role "user" can do nothing but
// what a bucket policy grants it: it owns no bucket and creates none the
// chart relies on.
type iamAccount struct {
	Access    string `json:"access"`
	Secret    string `json:"secret"`
	Role      string `json:"role"`
	UserID    int    `json:"userID"`
	GroupID   int    `json:"groupID"`
	ProjectID int    `json:"projectID"`
}

type iamConfig struct {
	AccessAccounts map[string]iamAccount `json:"accessAccounts"`
}

// RunIAM parses args (everything after the subcommand name), writes the
// IAM file and returns the exit code: 0 on success, 1 on failure, 2 for a
// usage or configuration error.
func RunIAM(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("farmer "+IAMCommand, flag.ContinueOnError)
	fs.SetOutput(stderr)
	usersDir := fs.String("users-dir", "", "directory with one subdirectory per user, each holding "+AccessKeyIDFile+" and "+SecretAccessKeyFile)
	rootDir := fs.String("root-dir", "", "directory holding the gateway root credential's "+AccessKeyIDFile+" (no user may have it)")
	out := fs.String("out", "", "IAM directory to write "+IAMFile+" to")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: farmer %s -users-dir DIR -root-dir DIR -out DIR\n\n", IAMCommand)
		fmt.Fprintf(stderr, "Writes the Versity Gateway's internal IAM file from mounted credentials.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *usersDir == "" || *rootDir == "" || *out == "" {
		fs.Usage()
		return 2
	}
	n, err := WriteIAM(*usersDir, *rootDir, *out)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", IAMCommand, err)
		if errors.Is(err, errUsage) {
			return 2
		}
		return 1
	}
	fmt.Fprintf(stderr, "%s: wrote %d users to %s\n", IAMCommand, n, filepath.Join(*out, IAMFile))
	return 0
}

// WriteIAM writes outDir/users.json with every user under usersDir, each
// with role "user", and returns how many it wrote. The file is written to
// a temporary file and renamed, mode 0400: the gateway only reads it.
func WriteIAM(usersDir, rootDir, outDir string) (int, error) {
	root, err := readCredential(rootDir, "", false)
	if err != nil {
		return 0, err
	}
	users, err := readUsers(usersDir, root.Access, true)
	if err != nil {
		return 0, err
	}
	conf := iamConfig{AccessAccounts: map[string]iamAccount{}}
	for _, u := range users {
		conf.AccessAccounts[u.Access] = iamAccount{Access: u.Access, Secret: u.Secret, Role: "user"}
	}
	b, err := json.Marshal(conf)
	if err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(outDir, "."+IAMFile+"-*")
	if err != nil {
		return 0, fmt.Errorf("writing %s: %w", IAMFile, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return 0, fmt.Errorf("writing %s: %w", IAMFile, err)
	}
	if err := tmp.Chmod(0o400); err != nil {
		tmp.Close()
		return 0, fmt.Errorf("writing %s: %w", IAMFile, err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("writing %s: %w", IAMFile, err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(outDir, IAMFile)); err != nil {
		return 0, fmt.Errorf("writing %s: %w", IAMFile, err)
	}
	return len(users), nil
}
