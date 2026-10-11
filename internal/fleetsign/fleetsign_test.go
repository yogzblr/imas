package fleetsign

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testChecksum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

// No URL, file name or checksum on the wire: the sprout derives the file
// name (ExpectedFileName) and takes the hash from the signed
// checksums.txt.
func TestManifest_HasNoURLOrFileName(t *testing.T) {
	typ := reflect.TypeOf(Manifest{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.ToLower(f.Name + f.Tag.Get("json"))
		for _, bad := range []string{"url", "file_name", "filename", "checksum_sha256"} {
			if strings.Contains(name, bad) {
				t.Errorf("Manifest field %s (%s) looks like %s", f.Name, f.Tag.Get("json"), bad)
			}
		}
	}
}

// TestNoSigningCodeInPackage keeps this package's shape honest: it is
// imported by farmer, saasapi and sprout, none of which may sign. The
// release key signs checksums.txt in the release workflow; this only
// catches someone adding signing code here by accident.
func TestNoSigningCodeInPackage(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"/sign/", "ed25519.Sign(", "ed25519.PrivateKey", "/rotate",
			"DetachSign", "openpgp.Sign(", "NewEntity", "NewSignerPrivateKey", ".SignUserId", ".SignKey"} {
			if strings.Contains(string(src), forbidden) {
				t.Errorf("%s contains %q: fleetsign must stay verify-only", f, forbidden)
			}
		}
	}
}
