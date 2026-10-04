//go:build !windows

package selfupdate

import "fmt"

// readMSIProperties needs the Windows Installer API (msi_windows.go). An
// MSI is only ever installed on Windows; this keeps the seam buildable
// elsewhere.
func readMSIProperties(string, []string) (map[string]string, error) {
	return nil, fmt.Errorf("%w: reading an MSI needs Windows", ErrUnsupportedPlatform)
}
