package certs

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
)

// ErrFarmerNKeyNotGenerated is GenNKey(true)'s error: farmer's NKey is the
// shared Secret every replica mounts (LoadFarmerNKey), never generated.
var ErrFarmerNKeyNotGenerated = fmt.Errorf("certs: farmer's NKey is never generated: mount its seed and set %s", config.EnvFarmerNKeySeedFile)

func GetPubNKey(isFarmer bool) (string, error) {
	if isFarmer {
		kp, err := LoadFarmerNKey()
		if err != nil {
			return "", err
		}
		defer kp.Wipe()
		return kp.PublicKey()
	}
	pubKeyBytes, err := os.ReadFile(config.NKeySproutPubFile)
	if err != nil {
		return "", err
	}
	return string(pubKeyBytes), nil
}

// LoadFarmerNKey reads farmer's NKey seed from config.NKeyFarmerPrivFile,
// the Secret key mounted read-only at IMAS_FARMER_NKEY_SEED_FILE. Every
// farmer replica mounts the same Secret, so all of them authenticate as
// the same NATS user. It writes nothing and refuses anything but a
// user-kind seed. The caller wipes the returned key pair.
func LoadFarmerNKey() (nkeys.KeyPair, error) {
	path := config.NKeyFarmerPrivFile
	if path == "" {
		return nil, fmt.Errorf("certs: farmer's NKey seed file is not set: mount the farmer NKey Secret and set %s", config.EnvFarmerNKeySeedFile)
	}
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("certs: reading farmer's NKey seed %s: %w", path, err)
	}
	kp, err := nkeys.FromSeed([]byte(strings.TrimSpace(string(seed))))
	if err != nil {
		return nil, fmt.Errorf("certs: farmer's NKey seed %s: %w", path, err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		kp.Wipe()
		return nil, fmt.Errorf("certs: farmer's NKey public key: %w", err)
	}
	if nkeys.Prefix(pub) != nkeys.PrefixByteUser {
		kp.Wipe()
		return nil, errors.New("certs: farmer's NKey seed is not a user key")
	}
	return kp, nil
}

// GenNKey creates the sprout's NKey on first start. Farmer's NKey is not
// generated (ErrFarmerNKeyNotGenerated): it comes from a Secret
// (LoadFarmerNKey).
func GenNKey(isFarmer bool) error {
	if isFarmer {
		return ErrFarmerNKeyNotGenerated
	}
	privFile := config.NKeySproutPrivFile
	pubFile := config.NKeySproutPubFile
	_, err := os.Stat(privFile)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat NKey file %s: %w", privFile, err)
	}
	kp, err := nkeys.CreateUser()
	if err != nil {
		return fmt.Errorf("failed to create NKey user: %w", err)
	}
	key, err := kp.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to get NKey public key: %w", err)
	}
	if err := os.WriteFile(pubFile, []byte(key), 0o600); err != nil {
		return fmt.Errorf("failed to write NKey public key to %s: %w", pubFile, err)
	}
	seed, err := kp.Seed()
	if err != nil {
		return fmt.Errorf("failed to get NKey seed: %w", err)
	}
	if err := os.WriteFile(privFile, seed, 0o600); err != nil {
		return fmt.Errorf("failed to write NKey private key to %s: %w", privFile, err)
	}
	return nil
}
