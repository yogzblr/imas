package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
)

// listFiles returns every path under root.
func listFiles(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

// TestFarmerNKeyFromReadOnlySecret: farmer's start path reads its NKey
// from the mounted Secret under a read-only root and writes nothing, and
// two replicas mounting the same Secret are the same NATS user.
func TestFarmerNKeyFromReadOnlySecret(t *testing.T) {
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := user.Seed()
	wantPub, _ := user.PublicKey()

	root := t.TempDir()
	secretDir := filepath.Join(root, "var/run/secrets/imas/farmer-nkey")
	if err := os.MkdirAll(secretDir, 0o755); err != nil {
		t.Fatal(err)
	}
	seedFile := filepath.Join(secretDir, "farmer.nk")
	if err := os.WriteFile(seedFile, seed, 0o440); err != nil {
		t.Fatal(err)
	}
	// The pod's root filesystem is read-only.
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		return os.Chmod(path, 0o555)
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(path, 0o755)
			}
			return nil
		})
	})
	before := listFiles(t, root)

	saved := []string{config.NKeyFarmerPrivFile, config.NKeyFarmerPubFile}
	t.Cleanup(func() {
		config.NKeyFarmerPrivFile, config.NKeyFarmerPubFile = saved[0], saved[1]
	})
	config.NKeyFarmerPrivFile = seedFile
	config.NKeyFarmerPubFile = ""

	for replica := range 2 {
		if err := checkFarmerNKey(); err != nil {
			t.Fatalf("replica %d: checkFarmerNKey: %v", replica, err)
		}
		if got := farmerNKeyPublic(); got != wantPub {
			t.Errorf("replica %d: farmerNKeyPublic = %q, want %s", replica, got, wantPub)
		}
		got, err := farmerNKeySeed()
		if err != nil || got != string(seed) {
			t.Errorf("replica %d: farmerNKeySeed = %v, want the Secret's seed", replica, err)
		}
	}
	if after := listFiles(t, root); strings.Join(after, "\n") != strings.Join(before, "\n") {
		t.Errorf("files changed under the read-only root:\nbefore %v\nafter  %v", before, after)
	}
}

// TestFarmerNKeyRequired: without the Secret farmer refuses to start, and
// creates no key in its place.
func TestFarmerNKeyRequired(t *testing.T) {
	saved := config.NKeyFarmerPrivFile
	t.Cleanup(func() { config.NKeyFarmerPrivFile = saved })

	config.NKeyFarmerPrivFile = ""
	if err := checkFarmerNKey(); err == nil || !strings.Contains(err.Error(), config.EnvFarmerNKeySeedFile) {
		t.Errorf("unset: err = %v, want one naming %s", err, config.EnvFarmerNKeySeedFile)
	}

	config.NKeyFarmerPrivFile = filepath.Join(t.TempDir(), "farmer.nk")
	if err := checkFarmerNKey(); err == nil {
		t.Error("missing seed: no error")
	}
	if _, err := os.Stat(config.NKeyFarmerPrivFile); !os.IsNotExist(err) {
		t.Errorf("checkFarmerNKey created %s", config.NKeyFarmerPrivFile)
	}
}
