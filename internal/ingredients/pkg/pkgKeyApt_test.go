package pkg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/yogzblr/imas/internal/cook"
)

const (
	dockerKeyURL = "https://download.docker.com/linux/ubuntu/gpg"
	otherKeyURL  = "https://b.example/repo/gpg" // same last element as dockerKeyURL
)

// testKey returns a fresh public key, armored and binary.
func testKey(t *testing.T, name string) (armored, binary []byte) {
	t.Helper()
	e, err := openpgp.NewEntity(name, "", name+"@example.com", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}
	var bin bytes.Buffer
	if err := e.Serialize(&bin); err != nil {
		t.Fatal(err)
	}
	var arm bytes.Buffer
	w, err := armor.Encode(&arm, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(bin.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return arm.Bytes(), bin.Bytes()
}

// withAptKeys points aptKeyringDir at a temporary directory, serves keys
// (URL → body) from fetchURLKey and installs a mock apt manager. It
// returns the directory and the mock.
func withAptKeys(t *testing.T, keys map[string][]byte) (string, *mockManager) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keyrings")
	origDir, origFetch := aptKeyringDir, fetchURLKey
	aptKeyringDir = dir
	fetchURLKey = func(_ context.Context, url string) ([]byte, error) {
		k, ok := keys[url]
		if !ok {
			return nil, fmt.Errorf("fetch key %s: 404 Not Found", url)
		}
		return k, nil
	}
	mock := newMock()
	mock.name = "apt"
	restore := withManager(mock)
	t.Cleanup(func() {
		aptKeyringDir, fetchURLKey = origDir, origFetch
		restore()
	})
	return dir, mock
}

func applyKey(t *testing.T, url string, test bool) cook.Result {
	t.Helper()
	p := Pkg{name: url, method: "key_managed", properties: map[string]interface{}{"name": url}}
	var (
		r   cook.Result
		err error
	)
	if test {
		r, err = p.Test(context.Background())
	} else {
		r, err = p.Apply(context.Background())
	}
	if err != nil {
		t.Fatalf("%s: %v", url, err)
	}
	return r
}

func mustHold(t *testing.T, name string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s does not hold the expected key", name)
	}
}

// TestKeyManagedAptSameBaseURLs: two URLs whose last element is the same
// both install, each into its own file, and a second run of either
// reports no change.
func TestKeyManagedAptSameBaseURLs(t *testing.T) {
	armA, binA := testKey(t, "a")
	armB, binB := testKey(t, "b")
	_, mock := withAptKeys(t, map[string][]byte{dockerKeyURL: armA, otherKeyURL: armB})
	legacy, uniqueA := aptKeyringPaths(dockerKeyURL)
	_, uniqueB := aptKeyringPaths(otherKeyURL)

	if r := applyKey(t, dockerKeyURL, false); !r.Changed {
		t.Fatalf("first key, first run: %+v; want a change", r)
	}
	mustHold(t, legacy, binA) // snack's name, as UAT I.pkg.key_managed checks
	if r := applyKey(t, otherKeyURL, false); !r.Changed {
		t.Fatalf("second key, first run: %+v; want a change", r)
	}
	mustHold(t, uniqueB, binB)
	mustHold(t, legacy, binA)
	for _, url := range []string{dockerKeyURL, otherKeyURL} {
		if r := applyKey(t, url, false); r.Changed || !r.Succeeded {
			t.Errorf("%s, second run: %+v; want no change", url, r)
		}
		if r := applyKey(t, url, true); r.Changed || !r.Succeeded {
			t.Errorf("%s, test run: %+v; want no change", url, r)
		}
	}
	if _, err := os.Stat(uniqueA); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s written for a key already in %s", uniqueA, legacy)
	}
	if mock.addKeyCalled != "" {
		t.Errorf("snack's AddKey called with %q", mock.addKeyCalled)
	}
}

// TestKeyManagedAptKeyFromSnack: a key snack's AddKey installed (gpg
// --dearmor into /etc/apt/keyrings/<base>.gpg) is found where it is.
func TestKeyManagedAptKeyFromSnack(t *testing.T) {
	arm, bin := testKey(t, "a")
	dir, _ := withAptKeys(t, map[string][]byte{dockerKeyURL: arm})
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gpg.gpg"), bin, 0o644); err != nil {
		t.Fatal(err)
	}
	if r := applyKey(t, dockerKeyURL, false); r.Changed || !r.Succeeded {
		t.Fatalf("%+v; want no change", r)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("keyrings holds %d files, want 1", len(entries))
	}
}

// TestKeyManagedAptTestMode: a test run reports where the key would go
// and writes nothing.
func TestKeyManagedAptTestMode(t *testing.T) {
	arm, _ := testKey(t, "a")
	dir, _ := withAptKeys(t, map[string][]byte{dockerKeyURL: arm})
	r := applyKey(t, dockerKeyURL, true)
	if !r.Changed || !r.Succeeded {
		t.Fatalf("%+v; want a change", r)
	}
	if want := "would add key: " + dockerKeyURL + " to " + filepath.Join(dir, "gpg.gpg"); r.Notes[0].String() != want {
		t.Errorf("note %q, want %q", r.Notes[0], want)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("test run created %s", dir)
	}
}

// TestKeyManagedAptRotatedKey: when the URL serves a new key, the URL's
// own file is updated; snack's name, holding another URL's key, is left
// alone.
func TestKeyManagedAptRotatedKey(t *testing.T) {
	_, binOther := testKey(t, "other")
	_, binOld := testKey(t, "old")
	armNew, binNew := testKey(t, "new")
	dir, _ := withAptKeys(t, map[string][]byte{otherKeyURL: armNew})
	legacy, unique := aptKeyringPaths(otherKeyURL)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{legacy: binOther, unique: binOld} {
		if err := os.WriteFile(name, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if r := applyKey(t, otherKeyURL, false); !r.Changed {
		t.Fatalf("%+v; want a change", r)
	}
	mustHold(t, unique, binNew)
	mustHold(t, legacy, binOther)
	if fi, err := os.Stat(unique); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("%s: %v, %v; want mode 0644", unique, fi.Mode(), err)
	}
}

// TestKeyManagedAptBadKey: a failed fetch or a body that is no key fails
// the step and writes nothing.
func TestKeyManagedAptBadKey(t *testing.T) {
	const htmlURL = "https://c.example/gpg"
	dir, _ := withAptKeys(t, map[string][]byte{htmlURL: []byte("<html>not here</html>")})
	for _, url := range []string{htmlURL, "https://d.example/missing/gpg"} {
		p := Pkg{name: url, method: "key_managed", properties: map[string]interface{}{"name": url}}
		r, err := p.Apply(context.Background())
		if err == nil || r.Succeeded {
			t.Errorf("%s: %+v, %v; want a failure", url, r, err)
		}
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a failed step created %s", dir)
	}
}

func TestAptKeyringPaths(t *testing.T) {
	orig := aptKeyringDir
	aptKeyringDir = "/etc/apt/keyrings"
	defer func() { aptKeyringDir = orig }()
	for _, tt := range []struct{ url, legacy string }{
		{dockerKeyURL, "/etc/apt/keyrings/gpg.gpg"},
		{otherKeyURL, "/etc/apt/keyrings/gpg.gpg"},
		{"https://example.com/keys/repo.asc", "/etc/apt/keyrings/repo.gpg"},
	} {
		legacy, unique := aptKeyringPaths(tt.url)
		if legacy != tt.legacy {
			t.Errorf("%s: legacy %q, want %q", tt.url, legacy, tt.legacy)
		}
		prefix := strings.TrimSuffix(tt.legacy, ".gpg") + "-"
		if !strings.HasPrefix(unique, prefix) || !strings.HasSuffix(unique, ".gpg") || len(unique) != len(prefix)+12+len(".gpg") {
			t.Errorf("%s: unique %q, want %s<12 hex>.gpg", tt.url, unique, prefix)
		}
	}
	_, a := aptKeyringPaths(dockerKeyURL)
	_, b := aptKeyringPaths(otherKeyURL)
	if a == b {
		t.Errorf("both URLs map to %s", a)
	}
}

func TestIsAptURLKey(t *testing.T) {
	apt := newMock()
	apt.name = "apt"
	dnf := newMock()
	dnf.name = "dnf"
	for _, tt := range []struct {
		mgr  *mockManager
		key  string
		want bool
	}{
		{apt, dockerKeyURL, true},
		{apt, "http://example.com/key.asc", true},
		{apt, "ABCD1234", false},
		{apt, "/tmp/key.asc", false},
		{dnf, "https://example.com/RPM-GPG-KEY", false},
	} {
		if got := isAptURLKey(tt.mgr, tt.key); got != tt.want {
			t.Errorf("%s %s: %v, want %v", tt.mgr.name, tt.key, got, tt.want)
		}
	}
}

func TestDearmorKey(t *testing.T) {
	arm, bin := testKey(t, "a")
	if got, err := dearmorKey(arm); err != nil || !bytes.Equal(got, bin) {
		t.Errorf("armored key: %v; want its binary form", err)
	}
	if got, err := dearmorKey(append([]byte("\n"), arm...)); err != nil || !bytes.Equal(got, bin) {
		t.Errorf("armored key after a blank line: %v", err)
	}
	if got, err := dearmorKey(bin); err != nil || !bytes.Equal(got, bin) {
		t.Errorf("binary key: %v; want it unchanged", err)
	}
	var msg bytes.Buffer
	w, _ := armor.Encode(&msg, "PGP MESSAGE", nil)
	_, _ = w.Write(bin)
	_ = w.Close()
	corrupt := bytes.Replace(arm, []byte("\n="), []byte("\n=AAAA"), 1)
	for name, data := range map[string][]byte{
		"html":          []byte("<!doctype html><title>404</title>"),
		"empty":         nil,
		"message block": msg.Bytes(),
		"bad checksum":  corrupt,
		"signature":     {0xc2, 0x01, 0x00}, // new-format tag 2
	} {
		if _, err := dearmorKey(data); err == nil {
			t.Errorf("%s: accepted as a key", name)
		}
	}
}

func TestFetchURLKey(t *testing.T) {
	arm, _ := testKey(t, "a")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gpg":
			_, _ = w.Write(arm)
		case "/big":
			_, _ = w.Write(bytes.Repeat([]byte("x"), maxKeySize+1))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	orig := keyHTTPClient
	keyHTTPClient = srv.Client()
	defer func() { keyHTTPClient = orig }()

	got, err := fetchURLKey(context.Background(), srv.URL+"/gpg")
	if err != nil || !bytes.Equal(got, arm) {
		t.Errorf("/gpg: %v; want the key", err)
	}
	for _, p := range []string{"/missing", "/big"} {
		if _, err := fetchURLKey(context.Background(), srv.URL+p); err == nil {
			t.Errorf("%s: no error", p)
		}
	}
}
