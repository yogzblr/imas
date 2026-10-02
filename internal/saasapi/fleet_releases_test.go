package saasapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/fleetsign"
)

const (
	testOperatorToken         = "operator-token-0123456789abcdef-current"
	testOperatorTokenPrevious = "operator-token-0123456789abcdef-previous"
	testFleetReleaserToken    = "saasapi-to-fleetreleaser-0123456789abcdef"
)

var (
	sumA = strings.Repeat("a1", 32)
	sumB = strings.Repeat("b2", 32)
	sumC = strings.Repeat("c3", 32)
)

// fakeSigner stands in for cmd/fleetreleaser: it signs with the test fleet
// key unless told to refuse, fail, or sign with some other key.
type fakeSigner struct {
	mu     sync.Mutex
	calls  []fleetsign.Manifest
	refuse *signRefusedError
	err    error
	// failAfter, when > 0, makes calls after the first failAfter fail.
	failAfter int
	// wrongKey signs with a key the key set doesn't hold.
	wrongKey bool
}

func (f *fakeSigner) Sign(_ context.Context, m fleetsign.Manifest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, m)
	switch {
	case f.refuse != nil:
		return "", f.refuse
	case f.err != nil:
		return "", f.err
	case f.failAfter > 0 && len(f.calls) > f.failAfter:
		return "", errSignerUnavailable
	}
	if m.Signature != "" {
		return "", errors.New("fakeSigner: asked to sign a manifest that already has a signature")
	}
	msg, err := m.Message()
	if err != nil {
		return "", err
	}
	priv, _ := testFleetKey(nil)
	if f.wrongKey {
		_, priv, _ = ed25519.GenerateKey(rand.Reader)
	}
	return fleetsign.EncodeSignature(1, ed25519.Sign(priv, msg)), nil
}

func (f *fakeSigner) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// newOperatorTest sets up the database, the read-only test key set and an
// operator plane over signer, and returns the operator router.
func newOperatorTest(t *testing.T, signer releaseSigner) (*gorm.DB, http.Handler) {
	t.Helper()
	gdb := newFleetTestDB(t)
	withTestFleetKeys(t)
	p := &operatorPlane{tokens: [][]byte{[]byte(testOperatorToken), []byte(testOperatorTokenPrevious)}, signer: signer}
	return gdb, p.router()
}

func releaseBody(version, minSprout string, pkgs ...fleetReleasePackage) fleetReleaseRequest {
	return fleetReleaseRequest{Version: version, Channel: "stable", MinSproutVersion: minSprout, Packages: pkgs}
}

func debPkg(arch, sum string) fleetReleasePackage {
	return fleetReleasePackage{OS: "linux", Arch: arch, PackageType: "deb",
		FileName: "imas-sprout_2.4.1_" + arch + ".deb", ChecksumSHA256: sum}
}

func msiPkg(sum string) fleetReleasePackage {
	return fleetReleasePackage{OS: "windows", Arch: "amd64", PackageType: "msi",
		FileName: "imas-sprout_2.4.1_amd64.msi", ChecksumSHA256: sum}
}

// operatorDo sends an operator request with token as the bearer (none if
// empty). body is JSON-encoded unless it's a string.
func operatorDo(t *testing.T, h http.Handler, token, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		r = strings.NewReader(b)
	default:
		data, _ := json.Marshal(b)
		r = strings.NewReader(string(data))
	}
	req := httptest.NewRequest(method, path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func register(t *testing.T, h http.Handler, body any) (int, map[string]any) {
	t.Helper()
	return operatorDo(t, h, testOperatorToken, http.MethodPost, "/v1/operator/fleet-releases", body)
}

func revoke(t *testing.T, h http.Handler, version string) (int, map[string]any) {
	t.Helper()
	return operatorDo(t, h, testOperatorToken, http.MethodPost, "/v1/operator/fleet-releases/"+version+"/revoke", nil)
}

func releaseRows(t *testing.T, gdb *gorm.DB, version string) []FleetVersion {
	t.Helper()
	rows, err := loadReleaseRows(gdb, version, false)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func countRows(t *testing.T, gdb *gorm.DB) int64 {
	t.Helper()
	var n int64
	gdb.Model(&FleetVersion{}).Count(&n)
	return n
}

func TestRegisterFleetRelease_StoresVerifiedRows(t *testing.T) {
	signer := &fakeSigner{}
	gdb, h := newOperatorTest(t, signer)

	code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA), debPkg("arm64", sumB), msiPkg(sumC)))
	if code != http.StatusCreated || resp["created"] != float64(3) || resp["revoked"] != false ||
		resp["version"] != "v2.4.1" || resp["min_sprout_version"] != "v2.0.0" {
		t.Fatalf("register = %d %v", code, resp)
	}
	if signer.n() != 3 {
		t.Fatalf("fleetreleaser called %d times, want once per package", signer.n())
	}
	rows := releaseRows(t, gdb, "v2.4.1")
	if len(rows) != 3 {
		t.Fatalf("%d rows stored", len(rows))
	}
	_, ks := testFleetKey(t)
	for _, row := range rows {
		if err := ks.Verify(row.Manifest()); err != nil {
			t.Errorf("%s/%s stored signature does not verify: %v", row.OS, row.Arch, err)
		}
		if !strings.HasPrefix(row.ID, "fv_") || row.Revoked || row.ReleasedAt.IsZero() || row.MinSproutVersion != "v2.0.0" {
			t.Errorf("row = %+v", row)
		}
	}
	if rows[2].OS != "windows" || rows[2].PackageType != "msi" || rows[2].ChecksumSHA256 != sumC {
		t.Fatalf("windows row = %+v", rows[2])
	}
	pkgs := resp["packages"].([]any)
	if len(pkgs) != 3 || pkgs[0].(map[string]any)["signature"] != rows[0].Signature {
		t.Fatalf("response packages = %v", pkgs)
	}
}

// Same version, same checksums: a 200 no-op, with no call to fleetreleaser
// (so re-running the Helm hook doesn't depend on the signer, or on the
// version still being above its floor).
func TestRegisterFleetRelease_SameReleaseIsNoOp(t *testing.T) {
	signer := &fakeSigner{}
	gdb, h := newOperatorTest(t, signer)
	body := releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA), msiPkg(sumC))
	if code, resp := register(t, h, body); code != http.StatusCreated {
		t.Fatalf("first register = %d %v", code, resp)
	}
	before := releaseRows(t, gdb, "v2.4.1")

	signer.err = errors.New("fleetreleaser is down")
	for i := range 2 {
		code, resp := register(t, h, body)
		if code != http.StatusOK || resp["created"] != float64(0) || len(resp["packages"].([]any)) != 2 {
			t.Fatalf("re-register %d = %d %v", i, code, resp)
		}
	}
	// A subset of an already registered release is a no-op too.
	if code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", msiPkg(sumC))); code != http.StatusOK || resp["created"] != float64(0) {
		t.Fatalf("subset = %d %v", code, resp)
	}
	if signer.n() != 2 {
		t.Fatalf("fleetreleaser called %d times, want 2 (first registration only)", signer.n())
	}
	after := releaseRows(t, gdb, "v2.4.1")
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("row changed by a no-op registration:\n%+v\n%+v", before[i], after[i])
		}
	}
}

// One linux/amd64 binary ships as a .deb and an .rpm: both register, as
// two rows signed separately, and re-registering either is a no-op.
func TestRegisterFleetRelease_DebAndRPMForOneOSArch(t *testing.T) {
	signer := &fakeSigner{}
	gdb, h := newOperatorTest(t, signer)
	rpm := fleetReleasePackage{OS: "linux", Arch: "amd64", PackageType: "rpm", FileName: "imas-sprout_2.4.1_linux_amd64.rpm", ChecksumSHA256: sumB}
	if code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA), rpm)); code != http.StatusCreated || resp["created"] != float64(2) {
		t.Fatalf("register = %d %v", code, resp)
	}
	rows := releaseRows(t, gdb, "v2.4.1")
	if len(rows) != 2 || rows[0].PackageType != "deb" || rows[1].PackageType != "rpm" ||
		rows[0].Signature == "" || rows[1].Signature == "" || rows[0].Signature == rows[1].Signature {
		t.Fatalf("rows = %+v", rows)
	}
	if code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", rpm)); code != http.StatusOK || resp["created"] != float64(0) {
		t.Fatalf("re-register rpm = %d %v", code, resp)
	}
	changed := rpm
	changed.ChecksumSHA256 = sumC
	if code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", changed)); code != http.StatusConflict {
		t.Fatalf("rpm with another checksum = %d %v, want 409", code, resp)
	}
	if signer.n() != 2 {
		t.Fatalf("fleetreleaser called %d times, want 2", signer.n())
	}
}

// Same version with different contents is 409, and nothing changes.
func TestRegisterFleetRelease_ConflictIs409(t *testing.T) {
	signer := &fakeSigner{}
	gdb, h := newOperatorTest(t, signer)
	if code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA))); code != http.StatusCreated {
		t.Fatalf("register = %d %v", code, resp)
	}
	before := releaseRows(t, gdb, "v2.4.1")

	renamed := debPkg("amd64", sumA)
	renamed.FileName = "imas-sprout_2.4.1-1_amd64.deb"
	for name, body := range map[string]fleetReleaseRequest{
		"different checksum":           releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumB)),
		"different checksum, plus new": releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumB), msiPkg(sumC)),
		"different file_name":          releaseBody("v2.4.1", "v2.0.0", renamed),
		"different min_sprout_version": releaseBody("v2.4.1", "v1.0.0", debPkg("amd64", sumA)),
		"new package, different floor": releaseBody("v2.4.1", "v1.0.0", msiPkg(sumC)),
	} {
		code, resp := register(t, h, body)
		if code != http.StatusConflict || resp["error"] != "release_conflict" {
			t.Errorf("%s: %d %v, want 409 release_conflict", name, code, resp)
		}
	}
	if signer.n() != 1 {
		t.Fatalf("fleetreleaser called %d times; a conflicting release must not be signed", signer.n())
	}
	after := releaseRows(t, gdb, "v2.4.1")
	if len(after) != 1 || after[0] != before[0] {
		t.Fatalf("rows changed by a refused registration: %+v", after)
	}
}

// A package for an OS/arch the version doesn't have yet is added, signed,
// with the version's existing release time.
func TestRegisterFleetRelease_AddsPackageToVersion(t *testing.T) {
	signer := &fakeSigner{}
	gdb, h := newOperatorTest(t, signer)
	if code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA))); code != http.StatusCreated {
		t.Fatalf("register = %d %v", code, resp)
	}
	first := releaseRows(t, gdb, "v2.4.1")[0]
	code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA), msiPkg(sumC)))
	if code != http.StatusCreated || resp["created"] != float64(1) || len(resp["packages"].([]any)) != 2 {
		t.Fatalf("register with a new package = %d %v", code, resp)
	}
	if signer.n() != 2 || signer.calls[1].OS != "windows" {
		t.Fatalf("signed %d time(s): %+v", signer.n(), signer.calls)
	}
	rows := releaseRows(t, gdb, "v2.4.1")
	if rows[0] != first || !rows[1].ReleasedAt.Equal(first.ReleasedAt) {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestRegisterFleetRelease_Validation(t *testing.T) {
	signer := &fakeSigner{}
	gdb, h := newOperatorTest(t, signer)
	valid := releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA))
	with := func(mutate func(*fleetReleaseRequest)) fleetReleaseRequest {
		r := valid
		r.Packages = append([]fleetReleasePackage(nil), valid.Packages...)
		mutate(&r)
		return r
	}
	pkg := func(mutate func(*fleetReleasePackage)) fleetReleaseRequest {
		return with(func(r *fleetReleaseRequest) { mutate(&r.Packages[0]) })
	}
	many := make([]fleetReleasePackage, maxReleasePackages+1)
	for i := range many {
		many[i] = debPkg("arch"+string(rune('a'+i)), sumA)
	}
	cases := map[string]any{
		"not JSON":               "nope",
		"array":                  "[]",
		"unknown field":          `{"version":"v2.4.1","channel":"stable","min_sprout_version":"v2.0.0","packages":[],"artifact_url":"https://evil.test/x"}`,
		"unknown package field":  `{"version":"v2.4.1","channel":"stable","min_sprout_version":"v2.0.0","packages":[{"os":"linux","arch":"amd64","package_type":"deb","file_name":"a.deb","checksum_sha256":"` + sumA + `","signature":"v1:x"}]}`,
		"trailing data":          `{"version":"v2.4.1","channel":"stable","min_sprout_version":"v2.0.0","packages":[]} {}`,
		"no packages":            with(func(r *fleetReleaseRequest) { r.Packages = nil }),
		"too many packages":      with(func(r *fleetReleaseRequest) { r.Packages = many }),
		"no channel":             with(func(r *fleetReleaseRequest) { r.Channel = "" }),
		"bad channel":            with(func(r *fleetReleaseRequest) { r.Channel = "Stable Channel" }),
		"no version":             with(func(r *fleetReleaseRequest) { r.Version = "" }),
		"non-canonical version":  with(func(r *fleetReleaseRequest) { r.Version = "2.4.1" }),
		"min above version":      with(func(r *fleetReleaseRequest) { r.MinSproutVersion = "v3.0.0" }),
		"uppercase checksum":     pkg(func(p *fleetReleasePackage) { p.ChecksumSHA256 = strings.ToUpper(sumA) }),
		"short checksum":         pkg(func(p *fleetReleasePackage) { p.ChecksumSHA256 = "abc" }),
		"path in file_name":      pkg(func(p *fleetReleasePackage) { p.FileName = "pool/main/imas-sprout.deb" }),
		"dot-dot file_name":      pkg(func(p *fleetReleasePackage) { p.FileName = "../imas-sprout.deb" }),
		"url as file_name":       pkg(func(p *fleetReleasePackage) { p.FileName = "https://evil.test/imas-sprout.deb" }),
		"uppercase os":           pkg(func(p *fleetReleasePackage) { p.OS = "Linux" }),
		"unknown package_type":   pkg(func(p *fleetReleasePackage) { p.PackageType = "apk"; p.FileName = "imas-sprout.apk" }),
		"msi on linux":           pkg(func(p *fleetReleasePackage) { p.PackageType = "msi"; p.FileName = "imas-sprout.msi" }),
		"deb on windows":         pkg(func(p *fleetReleasePackage) { p.OS = "windows" }),
		"file_name not .deb":     pkg(func(p *fleetReleasePackage) { p.FileName = "imas-sprout_2.4.1_amd64.rpm" }),
		"darwin":                 pkg(func(p *fleetReleasePackage) { p.OS = "darwin" }),
		"duplicate os/arch/type": with(func(r *fleetReleaseRequest) { r.Packages = append(r.Packages, debPkg("amd64", sumB)) }),
		"duplicate, same pkg":    with(func(r *fleetReleaseRequest) { r.Packages = append(r.Packages, r.Packages[0]) }),
	}
	for name, body := range cases {
		code, resp := register(t, h, body)
		if code != http.StatusBadRequest || (resp["error"] != "invalid_request" && resp["error"] != "invalid_release") {
			t.Errorf("%s: %d %v, want 400", name, code, resp)
		}
	}
	if signer.n() != 0 || countRows(t, gdb) != 0 {
		t.Fatalf("invalid releases: %d signing call(s), %d row(s)", signer.n(), countRows(t, gdb))
	}
	if code, _ := register(t, h, strings.Repeat(" ", maxReleaseRequestBytes+1)+"{}"); code != http.StatusBadRequest {
		t.Fatalf("oversized body: %d", code)
	}
}

// fleetreleaser refusing (e.g. a version at or below its floor), failing,
// or returning a signature that doesn't verify: nothing is stored, not
// even the packages signed before the failure.
func TestRegisterFleetRelease_SigningFailuresStoreNothing(t *testing.T) {
	body := releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA), debPkg("arm64", sumB), msiPkg(sumC))
	for name, tc := range map[string]struct {
		signer *fakeSigner
		code   int
		err    string
	}{
		"refused (floor)": {&fakeSigner{refuse: &signRefusedError{Status: 422, Code: "version_not_above_floor",
			Message: "version v2.4.1 is at or below the version floor v2.5.0"}}, http.StatusUnprocessableEntity, "signing_refused"},
		"unavailable":          {&fakeSigner{err: errSignerUnavailable}, http.StatusBadGateway, "signer_unavailable"},
		"fails on second":      {&fakeSigner{failAfter: 1}, http.StatusBadGateway, "signer_unavailable"},
		"signature from a key": {&fakeSigner{wrongKey: true}, http.StatusBadGateway, "signer_unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			gdb, h := newOperatorTest(t, tc.signer)
			code, resp := register(t, h, body)
			if code != tc.code || resp["error"] != tc.err {
				t.Fatalf("register = %d %v, want %d %s", code, resp, tc.code, tc.err)
			}
			if n := countRows(t, gdb); n != 0 {
				t.Fatalf("%d row(s) stored", n)
			}
			if tc.signer.refuse != nil {
				details, _ := resp["details"].(map[string]any)
				if details["signer_error"] != "version_not_above_floor" {
					t.Fatalf("details = %v", resp["details"])
				}
			}
		})
	}
}

// Without the read-only key source a signature can't be checked, so
// nothing is signed or stored.
func TestRegisterFleetRelease_NeedsKeySource(t *testing.T) {
	signer := &fakeSigner{}
	gdb, h := newOperatorTest(t, signer)
	SetFleetKeySource(nil)
	code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA)))
	if code != http.StatusServiceUnavailable || signer.n() != 0 || countRows(t, gdb) != 0 {
		t.Fatalf("register without a key source = %d %v (%d signs)", code, resp, signer.n())
	}
	SetFleetKeySource(staticFleetKeys{err: errors.New("403 permission denied")})
	if code, _ := register(t, h, releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA))); code != http.StatusServiceUnavailable {
		t.Fatalf("register with an unreadable key = %d", code)
	}
}

func TestRevokeFleetRelease(t *testing.T) {
	signer := &fakeSigner{}
	gdb, h := newOperatorTest(t, signer)
	body := releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA), msiPkg(sumC))
	if code, resp := register(t, h, body); code != http.StatusCreated {
		t.Fatalf("register = %d %v", code, resp)
	}
	if code, resp := register(t, h, releaseBody("v2.4.2", "v2.0.0", debPkg("amd64", sumB))); code != http.StatusCreated {
		t.Fatalf("register v2.4.2 = %d %v", code, resp)
	}

	code, resp := revoke(t, h, "v2.4.1")
	if code != http.StatusOK || resp["revoked"] != true || resp["packages"] != float64(2) || resp["already_revoked"] != false {
		t.Fatalf("revoke = %d %v", code, resp)
	}
	for _, row := range releaseRows(t, gdb, "v2.4.1") {
		if !row.Revoked {
			t.Fatalf("row not revoked: %+v", row)
		}
	}
	if releaseRows(t, gdb, "v2.4.2")[0].Revoked {
		t.Fatal("revoking v2.4.1 revoked v2.4.2")
	}
	// Idempotent.
	if code, resp := revoke(t, h, "v2.4.1"); code != http.StatusOK || resp["already_revoked"] != true {
		t.Fatalf("revoke again = %d %v", code, resp)
	}
	// Re-registering the same release (a helm upgrade or rollback re-running
	// the hook) is a no-op that leaves it revoked.
	if code, resp := register(t, h, body); code != http.StatusOK || resp["revoked"] != true {
		t.Fatalf("re-register revoked = %d %v", code, resp)
	}
	// A revoked version takes no new packages, and a different build is
	// still a conflict.
	if code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", debPkg("arm64", sumB))); code != http.StatusConflict || resp["error"] != "version_revoked" {
		t.Fatalf("new package for revoked version = %d %v", code, resp)
	}
	if code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumB))); code != http.StatusConflict || resp["error"] != "release_conflict" {
		t.Fatalf("different build of revoked version = %d %v", code, resp)
	}
	for _, row := range releaseRows(t, gdb, "v2.4.1") {
		if !row.Revoked {
			t.Fatalf("re-registration un-revoked %+v", row)
		}
	}

	if code, resp := revoke(t, h, "v9.9.9"); code != http.StatusNotFound {
		t.Fatalf("revoke unknown = %d %v", code, resp)
	}
	for _, bad := range []string{"2.4.1", "v2.4", "v2.4.1+build", "latest"} {
		if code, _ := revoke(t, h, bad); code != http.StatusBadRequest {
			t.Errorf("revoke %q = %d, want 400", bad, code)
		}
	}
	if code, _ := operatorDo(t, h, testOperatorToken, http.MethodGet, "/v1/operator/fleet-releases/v2.4.1/revoke", nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("GET revoke = %d", code)
	}
}

// What revocation does to the tenant side: the version can't be newly
// approved, no rollout of it is created, and a rollout already under way
// stops before its next wave.
func TestRevokedVersionIsNotApprovableOrDispatched(t *testing.T) {
	gdb := newUpdateTestDB(t)
	tid := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustPublishVersion(t, gdb, "v2.4.2", time.Now())
	mustApprove(t, gdb, tid, "v2.4.2")
	p := &operatorPlane{tokens: [][]byte{[]byte(testOperatorToken)}, signer: &fakeSigner{}}
	h := p.router()

	if code, _ := revoke(t, h, "v2.4.1"); code != http.StatusOK {
		t.Fatal("revoke failed")
	}
	if w := patchPolicy(t, tid, `{"approved_version":"v2.4.1"}`); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "version_revoked") {
		t.Fatalf("approving a revoked version = %d %s", w.Code, w.Body.String())
	}

	// v2.4.2 is approved; revoking it stops new rollouts and running ones.
	if code, err := rolloutPolicyCheck(gdb, tid, "v2.4.2", time.Now()); code != "" || err != nil {
		t.Fatalf("before revoking: %q %v", code, err)
	}
	if code, _ := revoke(t, h, "v2.4.2"); code != http.StatusOK {
		t.Fatal("revoke failed")
	}
	if code, err := rolloutPolicyCheck(gdb, tid, "v2.4.2", time.Now()); code != errCodeVersionRevoked || err != nil {
		t.Fatalf("after revoking: %q %v, want %s", code, err, errCodeVersionRevoked)
	}
	code, resp := postUpdates(t, tid, map[string]any{"asset_ids": []string{"a1"}, "target_version": "v2.4.2"})
	if code != http.StatusConflict || resp["error"] != "version_revoked" {
		t.Fatalf("rollout of a revoked version = %d %v", code, resp)
	}
}

// The operator plane takes only the operator token: not the BFF's shared
// secret, not an end-user JWT, not saasapi's fleetreleaser token. And the
// two planes don't share routes.
func TestOperatorPlaneAuth(t *testing.T) {
	signer := &fakeSigner{}
	gdb, h := newOperatorTest(t, signer)
	auth := newTestAuthEnv(t)
	body, _ := json.Marshal(releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA)))

	for name, set := range map[string]func(r *http.Request){
		"no credentials":       func(*http.Request) {},
		"BFF secret and JWT":   func(r *http.Request) { auth.setAuthHeaders(r, "t_x") },
		"BFF secret as bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+testInternalAuthSecretCurrent) },
		"fleetreleaser token":  func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+testFleetReleaserToken) },
		"wrong token":          func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+testOperatorToken+"x") },
		"token prefix":         func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+testOperatorToken[:20]) },
		"no scheme":            func(r *http.Request) { r.Header.Set("Authorization", testOperatorToken) },
		"token in X-Internal-Auth": func(r *http.Request) {
			r.Header.Set(InternalAuthHeader, testOperatorToken)
		},
	} {
		for _, path := range []string{"/v1/operator/fleet-releases", "/v1/operator/fleet-releases/v2.4.1/revoke"} {
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
			set(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s on %s: %d %s, want 401", name, path, w.Code, w.Body.String())
			}
		}
	}
	if signer.n() != 0 || countRows(t, gdb) != 0 {
		t.Fatalf("unauthenticated requests: %d signing call(s), %d row(s)", signer.n(), countRows(t, gdb))
	}
	// The previous token still works during a rotation.
	if code, resp := operatorDo(t, h, testOperatorTokenPrevious, http.MethodPost, "/v1/operator/fleet-releases", string(body)); code != http.StatusCreated {
		t.Fatalf("previous operator token: %d %v", code, resp)
	}

	// The tenant API has no operator routes, even for a caller holding
	// valid BFF credentials or the operator token...
	tenantAPI := NewRouter()
	for _, path := range []string{"/v1/operator/fleet-releases", "/v1/operator/fleet-releases/v2.4.1/revoke"} {
		for _, set := range []func(*http.Request){
			func(r *http.Request) { auth.setAuthHeaders(r, "t_x") },
			func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+testOperatorToken) },
		} {
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body)))
			set(r)
			w := httptest.NewRecorder()
			tenantAPI.ServeHTTP(w, r)
			if w.Code != http.StatusNotFound {
				t.Errorf("tenant API %s: %d, want 404", path, w.Code)
			}
		}
	}
	// ...and the operator listener has no tenant routes.
	for _, path := range []string{"/v1/versions", "/v1/tenants", "/v1/tenants/t_x/update-policy"} {
		if code, _ := operatorDo(t, h, testOperatorToken, http.MethodGet, path, nil); code != http.StatusNotFound {
			t.Errorf("operator listener GET %s = %d, want 404", path, code)
		}
	}
}

// fakeFleetReleaser is cmd/fleetreleaser's POST /v1/sign as saasapi sees
// it, over TLS: it checks the bearer token and the six-field body, and
// signs with the test fleet key.
type fakeFleetReleaser struct {
	srv     *httptest.Server
	caFile  string
	reply   func(w http.ResponseWriter, fields map[string]string) bool
	mu      sync.Mutex
	authz   []string
	bodies  []map[string]string
	seenRaw []string
}

func newFakeFleetReleaser(t *testing.T) *fakeFleetReleaser {
	t.Helper()
	f := &fakeFleetReleaser{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var fields map[string]string
		_ = json.Unmarshal(raw, &fields)
		f.mu.Lock()
		f.authz = append(f.authz, r.Header.Get("Authorization"))
		f.bodies = append(f.bodies, fields)
		f.seenRaw = append(f.seenRaw, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+testFleetReleaserToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.reply != nil && f.reply(w, fields) {
			return
		}
		m := fleetsign.Manifest{Version: fields["version"], OS: fields["os"], Arch: fields["arch"], FileName: fields["file_name"],
			ChecksumSHA256: fields["checksum_sha256"], MinSproutVersion: fields["min_sprout_version"]}
		msg, err := m.Message()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_manifest", "message": err.Error()})
			return
		}
		priv, _ := testFleetKey(nil)
		json.NewEncoder(w).Encode(map[string]string{"signature": fleetsign.EncodeSignature(1, ed25519.Sign(priv, msg))})
	}))
	t.Cleanup(f.srv.Close)
	f.caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(f.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func writeSecret(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newTestFleetReleaserClient(t *testing.T, f *fakeFleetReleaser) *fleetReleaserClient {
	t.Helper()
	c, err := newFleetReleaserClient(f.srv.URL, writeSecret(t, testFleetReleaserToken+"\n"), f.caFile)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFleetReleaserClient(t *testing.T) {
	f := newFakeFleetReleaser(t)
	c := newTestFleetReleaserClient(t, f)
	m := FleetVersion{Version: "v2.4.1", OS: "linux", Arch: "amd64", FileName: "imas-sprout_2.4.1_amd64.deb",
		ChecksumSHA256: sumA, MinSproutVersion: "v2.0.0"}.Manifest()

	sig, err := c.Sign(t.Context(), m)
	if err != nil {
		t.Fatal(err)
	}
	_, ks := testFleetKey(t)
	signed := m
	signed.Signature = sig
	if err := ks.Verify(signed); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	// It sent the six fields, nothing else, with its own token, to /v1/sign.
	want := map[string]string{"version": "v2.4.1", "os": "linux", "arch": "amd64", "file_name": "imas-sprout_2.4.1_amd64.deb",
		"checksum_sha256": sumA, "min_sprout_version": "v2.0.0"}
	if len(f.bodies[0]) != len(want) || f.authz[0] != "Bearer "+testFleetReleaserToken || f.seenRaw[0] != "POST /v1/sign" {
		t.Fatalf("request: %s %q %v", f.seenRaw[0], f.authz[0], f.bodies[0])
	}
	for k, v := range want {
		if f.bodies[0][k] != v {
			t.Fatalf("request field %s = %q, want %q", k, f.bodies[0][k], v)
		}
	}

	for name, tc := range map[string]struct {
		reply   func(w http.ResponseWriter) bool
		refused bool
	}{
		"refusal 422": {func(w http.ResponseWriter) bool {
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write([]byte(`{"error":"version_not_above_floor","message":"at or below v3.0.0"}`))
			return true
		}, true},
		"refusal 400": {func(w http.ResponseWriter) bool {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_manifest","message":"bad"}`))
			return true
		}, true},
		"401":          {func(w http.ResponseWriter) bool { w.WriteHeader(http.StatusUnauthorized); return true }, false},
		"502":          {func(w http.ResponseWriter) bool { w.WriteHeader(http.StatusBadGateway); return true }, false},
		"not JSON":     {func(w http.ResponseWriter) bool { w.Write([]byte("ok")); return true }, false},
		"no signature": {func(w http.ResponseWriter) bool { w.Write([]byte(`{"signature":""}`)); return true }, false},
		"extra field":  {func(w http.ResponseWriter) bool { w.Write([]byte(`{"signature":"v1:x","url":"y"}`)); return true }, false},
		"redirect away": {func(w http.ResponseWriter) bool {
			w.Header().Set("Location", "https://evil.test/")
			w.WriteHeader(307)
			return true
		}, false},
	} {
		f.reply = func(w http.ResponseWriter, _ map[string]string) bool { return tc.reply(w) }
		_, err := c.Sign(t.Context(), m)
		var refused *signRefusedError
		if tc.refused != errors.As(err, &refused) || (!tc.refused && !errors.Is(err, errSignerUnavailable)) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// It trusts only the configured CA (or the system roots, which don't
	// hold httptest's).
	untrusting, err := newFleetReleaserClient(f.srv.URL, writeSecret(t, testFleetReleaserToken), "")
	if err != nil {
		t.Fatal(err)
	}
	f.reply = nil
	if _, err := untrusting.Sign(t.Context(), m); !errors.Is(err, errSignerUnavailable) {
		t.Fatalf("client without the CA = %v", err)
	}
}

func TestNewFleetReleaserClientConfig(t *testing.T) {
	tok := writeSecret(t, testFleetReleaserToken)
	for _, u := range []string{"http://fleetreleaser:8443", "https://", "https://u:p@fleetreleaser", "https://fleetreleaser/v1",
		"https://fleetreleaser?x=1", "fleetreleaser:8443", ""} {
		if _, err := newFleetReleaserClient(u, tok, ""); err == nil {
			t.Errorf("URL %q accepted", u)
		}
	}
	if _, err := newFleetReleaserClient("https://fleetreleaser:8443/", tok, ""); err != nil {
		t.Errorf("trailing slash refused: %v", err)
	}
	if _, err := newFleetReleaserClient("https://fleetreleaser:8443", writeSecret(t, "short"), ""); err == nil {
		t.Error("short token accepted")
	}
	if _, err := newFleetReleaserClient("https://fleetreleaser:8443", tok, writeSecret(t, "not a pem")); err == nil {
		t.Error("CA file without certificates accepted")
	}
}

// The whole path over the wire: operator plane → TLS → fleetreleaser
// stand-in → verify → store.
func TestRegisterFleetRelease_ThroughFleetReleaserClient(t *testing.T) {
	f := newFakeFleetReleaser(t)
	gdb, h := newOperatorTest(t, newTestFleetReleaserClient(t, f))
	code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA), msiPkg(sumC)))
	if code != http.StatusCreated || resp["created"] != float64(2) {
		t.Fatalf("register = %d %v", code, resp)
	}
	_, ks := testFleetKey(t)
	for _, row := range releaseRows(t, gdb, "v2.4.1") {
		if err := ks.Verify(row.Manifest()); err != nil {
			t.Fatalf("%s/%s: %v", row.OS, row.Arch, err)
		}
	}
	// fleetreleaser's refusal reaches the operator as a 422.
	f.reply = func(w http.ResponseWriter, _ map[string]string) bool {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"error":"version_not_above_floor","message":"version v2.4.2 is at or below the version floor v2.5.0"}`))
		return true
	}
	code, resp = register(t, h, releaseBody("v2.4.2", "v2.0.0", debPkg("amd64", sumB)))
	if code != http.StatusUnprocessableEntity || resp["error"] != "signing_refused" || len(releaseRows(t, gdb, "v2.4.2")) != 0 {
		t.Fatalf("register below floor = %d %v", code, resp)
	}
}

// writeTestCert writes a self-signed certificate and key, PEM, and returns
// their paths.
func writeTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "saasapi-operator"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certFile, keyFile
}

func TestNewOperatorServer(t *testing.T) {
	certFile, keyFile := writeTestCert(t)
	base := Config{
		InternalAuthSecretCurrent: testInternalAuthSecretCurrent,
		OperatorListenAddr:        ":0",
		OperatorTLSCertFile:       certFile,
		OperatorTLSKeyFile:        keyFile,
		OperatorTokenFile:         writeSecret(t, testOperatorToken+"\n"),
		FleetReleaserURL:          "https://fleetreleaser.imas.svc:8443",
		FleetReleaserTokenFile:    writeSecret(t, testFleetReleaserToken),
	}
	srv, err := NewOperatorServer(base)
	if err != nil {
		t.Fatal(err)
	}
	if srv.Addr != ":0" || srv.TLSConfig == nil || len(srv.TLSConfig.Certificates) != 1 || srv.Handler == nil {
		t.Fatalf("server = %+v", srv)
	}

	with := func(mutate func(*Config)) Config { c := base; mutate(&c); return c }
	for name, cfg := range map[string]Config{
		"off":                    with(func(c *Config) { c.OperatorListenAddr = "" }),
		"no cert":                with(func(c *Config) { c.OperatorTLSCertFile = "" }),
		"unreadable cert":        with(func(c *Config) { c.OperatorTLSCertFile = filepath.Join(t.TempDir(), "x") }),
		"no operator token":      with(func(c *Config) { c.OperatorTokenFile = "" }),
		"short operator token":   with(func(c *Config) { c.OperatorTokenFile = writeSecret(t, "short") }),
		"bad previous token":     with(func(c *Config) { c.OperatorTokenPreviousFile = writeSecret(t, "short") }),
		"http fleetreleaser":     with(func(c *Config) { c.FleetReleaserURL = "http://fleetreleaser:8443" }),
		"no fleetreleaser token": with(func(c *Config) { c.FleetReleaserTokenFile = "" }),
		"operator token is BFF's": with(func(c *Config) {
			c.OperatorTokenFile = writeSecret(t, testInternalAuthSecretCurrent+"-padded-to-length")
			c.InternalAuthSecretCurrent = testInternalAuthSecretCurrent + "-padded-to-length"
		}),
		"previous is BFF's previous": with(func(c *Config) {
			c.InternalAuthSecretPrevious = testOperatorTokenPrevious
			c.OperatorTokenPreviousFile = writeSecret(t, testOperatorTokenPrevious)
		}),
		"operator is fleetreleaser's": with(func(c *Config) { c.FleetReleaserTokenFile = c.OperatorTokenFile }),
	} {
		if _, err := NewOperatorServer(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadConfigOperatorPlane(t *testing.T) {
	set := map[string]string{
		"SAASAPI_OPERATOR_LISTEN_ADDR":     ":8443",
		"SAASAPI_OPERATOR_TLS_CERT_FILE":   "/tls/tls.crt",
		"SAASAPI_OPERATOR_TLS_KEY_FILE":    "/tls/tls.key",
		"SAASAPI_OPERATOR_TOKEN_FILE":      "/op/token",
		"SAASAPI_FLEETRELEASER_URL":        "https://fleetreleaser:8443",
		"SAASAPI_FLEETRELEASER_TOKEN_FILE": "/fr/token",
	}
	for k, v := range set {
		t.Setenv(k, v)
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OperatorListenAddr != ":8443" || cfg.FleetReleaserURL != "https://fleetreleaser:8443" || cfg.OperatorTokenFile != "/op/token" {
		t.Fatalf("config = %+v", cfg)
	}
	for k := range set {
		if k == "SAASAPI_OPERATOR_LISTEN_ADDR" {
			continue
		}
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, "")
			if _, err := LoadConfig(); err == nil {
				t.Fatalf("missing %s accepted", k)
			}
		})
	}
	t.Setenv("SAASAPI_FLEETRELEASER_URL", "http://fleetreleaser:8443")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("http fleetreleaser URL accepted")
	}
	// Off: nothing else is required.
	for k := range set {
		t.Setenv(k, "")
	}
	if cfg, err := LoadConfig(); err != nil || cfg.OperatorListenAddr != "" {
		t.Fatalf("operator plane off: %+v, %v", cfg, err)
	}
}
