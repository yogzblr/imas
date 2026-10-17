package fleetsign

import (
	"fmt"
	"io"
	"os"
)

// readTrustFile reads the keyring file at path, at most limit bytes.
// Whoever can write the keyring decides what the sprout installs as root,
// so it must pass CheckPrivateFile, checked on the path itself (Lstat):
// a regular file, not a symlink, owned by the effective user and no
// looser than 0600 (on Windows: owned by SYSTEM or Administrators, with
// no write for anyone else). The file that is then opened must be the
// one that was checked, so a rename between the two is refused too.
func readTrustFile(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("fleetsign: opening keyring: %w", err)
	}
	if err := checkFileInfo(path, before); err != nil {
		return nil, fmt.Errorf("fleetsign: keyring: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("fleetsign: opening keyring: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("fleetsign: stat keyring: %w", err)
	}
	if !os.SameFile(before, fi) {
		return nil, fmt.Errorf("fleetsign: keyring: %w: %s was replaced while it was being opened", ErrUnsafePath, path)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("fleetsign: reading keyring: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("fleetsign: keyring %s is larger than %d bytes", path, limit)
	}
	return data, nil
}
