package fleetsign

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

// readTrustFile reads the keyring file at path, at most limit bytes. It
// refuses anything but a regular file and, on Unix-like systems, a file
// that is group- or world-writable: whoever can write the keyring decides
// what the sprout installs as root. These are the same checks the legacy
// JSON LoadKeyring makes.
func readTrustFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("fleetsign: opening keyring: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("fleetsign: stat keyring: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("fleetsign: keyring %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("fleetsign: keyring %s is group- or world-writable (mode %v)", path, fi.Mode().Perm())
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
