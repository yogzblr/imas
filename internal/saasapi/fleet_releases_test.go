package saasapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/fleetsign"
)

const (
	testOperatorToken         = "operator-token-0123456789abcdef-current"
	testOperatorTokenPrevious = "operator-token-0123456789abcdef-previous"
	testOtherToken            = "some-other-service-token-0123456789abcdef"
)

var (
	sumA = strings.Repeat("a1", 32)
	sumB = strings.Repeat("b2", 32)
	sumC = strings.Repeat("c3", 32)
	sumT = strings.Repeat("d4", 32) // the release tarball, not a package
)

// newOperatorTest sets up the database and an operator plane, and returns
// the operator router.
func newOperatorTest(t *testing.T) (*gorm.DB, http.Handler) {
	t.Helper()
	gdb := newFleetTestDB(t)
	p := &operatorPlane{tokens: [][]byte{[]byte(testOperatorToken), []byte(testOperatorTokenPrevious)}}
	return gdb, p.router()
}

// checksumsFor is a goreleaser-style checksums.txt listing pkgs and the
// release tarball.
func checksumsFor(pkgs ...fleetReleasePackage) string {
	var b strings.Builder
	for _, p := range pkgs {
		b.WriteString(p.ChecksumSHA256 + "  " + p.FileName + "\n")
	}
	b.WriteString(sumT + "  imas_2.4.1_linux_amd64.tar.gz\n")
	return b.String()
}

// testSig stands in for checksums.txt.sig: saasapi never verifies it, so
// any bytes do.
func testSig(version string) string {
	return base64.StdEncoding.EncodeToString([]byte("detached signature over the checksums of " + version))
}

// releaseBody is a registration of pkgs whose checksums.txt lists exactly
// pkgs (and the tarball).
func releaseBody(version, minSprout string, pkgs ...fleetReleasePackage) fleetReleaseRequest {
	return fleetReleaseRequest{Version: version, Channel: "stable", MinSproutVersion: minSprout, Packages: pkgs,
		ChecksumsTxt: checksumsFor(pkgs...), ChecksumsSig: testSig(version)}
}

// withSums replaces r's checksums.txt with one listing all (and the
// tarball): the whole release's file, when r registers only some of it.
func (r fleetReleaseRequest) withSums(all ...fleetReleasePackage) fleetReleaseRequest {
	r.ChecksumsTxt = checksumsFor(all...)
	return r
}

func debPkg(arch, sum string) fleetReleasePackage {
	return fleetReleasePackage{OS: "linux", Arch: arch, PackageType: "deb",
		FileName: "imas-sprout_2.4.1_linux_" + arch + ".deb", ChecksumSHA256: sum}
}

func rpmPkg(arch, sum string) fleetReleasePackage {
	return fleetReleasePackage{OS: "linux", Arch: arch, PackageType: "rpm",
		FileName: "imas-sprout_2.4.1_linux_" + arch + ".rpm", ChecksumSHA256: sum}
}

func msiPkg(sum string) fleetReleasePackage {
	return fleetReleasePackage{OS: "windows", Arch: "amd64", PackageType: "msi",
		FileName: "imas-sprout-2.4.1-windows-x64.msi", ChecksumSHA256: sum}
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

// releaseChecksums returns version's stored checksums row, or nil.
func releaseChecksums(t *testing.T, gdb *gorm.DB, version string) *FleetReleaseChecksums {
	t.Helper()
	_, sums, err := loadRelease(gdb, version, false)
	if err != nil {
		t.Fatal(err)
	}
	return sums
}

func countRows(t *testing.T, gdb *gorm.DB) int64 {
	t.Helper()
	var n, m int64
	gdb.Model(&FleetVersion{}).Count(&n)
	gdb.Model(&FleetReleaseChecksums{}).Count(&m)
	return n + m
}

func TestRegisterFleetRelease_StoresRowsAndChecksums(t *testing.T) {
	gdb, h := newOperatorTest(t)
	body := releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA), debPkg("arm64", sumB), msiPkg(sumC))
	code, resp := register(t, h, body)
	if code != http.StatusCreated || resp["created"] != float64(3) || resp["revoked"] != false ||
		resp["version"] != "v2.4.1" || resp["min_sprout_version"] != "v2.0.0" {
		t.Fatalf("register = %d %v", code, resp)
	}
	rows := releaseRows(t, gdb, "v2.4.1")
	if len(rows) != 3 {
		t.Fatalf("%d rows stored", len(rows))
	}
	for _, row := range rows {
		if !strings.HasPrefix(row.ID, "fv_") || row.Revoked || row.ReleasedAt.IsZero() || row.MinSproutVersion != "v2.0.0" ||
			row.Signature != "" {
			t.Errorf("row = %+v", row)
		}
	}
	if rows[2].OS != "windows" || rows[2].PackageType != "msi" || rows[2].ChecksumSHA256 != sumC {
		t.Fatalf("windows row = %+v", rows[2])
	}
	sums := releaseChecksums(t, gdb, "v2.4.1")
	if sums == nil || sums.ChecksumsTxt != body.ChecksumsTxt || sums.ChecksumsSig != body.ChecksumsSig || sums.CreatedAt.IsZero() {
		t.Fatalf("checksums row = %+v", sums)
	}
	pkgs := resp["packages"].([]any)
	if len(pkgs) != 3 {
		t.Fatalf("response packages = %v", pkgs)
	}
	if _, ok := pkgs[0].(map[string]any)["signature"]; ok {
		t.Fatalf("response still carries a per-package signature: %v", pkgs[0])
	}
}

// TestRegisterFleetRelease_Checksums: the register endpoint's checks of
// checksums_txt and checksums_sig, and replays. saasapi verifies no
// signature (D20): any well-formed base64 is stored.
func TestRegisterFleetRelease_Checksums(t *testing.T) {
	good := releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA), msiPkg(sumC))
	with := func(mutate func(*fleetReleaseRequest)) fleetReleaseRequest {
		r := good
		mutate(&r)
		return r
	}
	debLine := sumA + "  imas-sprout_2.4.1_linux_amd64.deb\n"
	msiLine := sumC + "  imas-sprout-2.4.1-windows-x64.msi\n"
	for _, tc := range []struct {
		name string
		body fleetReleaseRequest
		code int
		err  string
		msg  string // in the message
	}{
		{name: "good", body: good, code: http.StatusCreated},
		{name: "trailing blank lines", body: with(func(r *fleetReleaseRequest) { r.ChecksumsTxt += "\n\n" }), code: http.StatusCreated},
		{name: "missing sig", body: with(func(r *fleetReleaseRequest) { r.ChecksumsSig = "" }),
			code: http.StatusBadRequest, err: "invalid_release", msg: "checksums_sig"},
		{name: "sig not base64", body: with(func(r *fleetReleaseRequest) { r.ChecksumsSig = "not base64!" }),
			code: http.StatusBadRequest, err: "invalid_release", msg: "checksums_sig"},
		{name: "missing checksums_txt", body: with(func(r *fleetReleaseRequest) { r.ChecksumsTxt = "" }),
			code: http.StatusBadRequest, err: "invalid_release", msg: "checksums_txt"},
		{name: "oversize checksums_txt", body: with(func(r *fleetReleaseRequest) {
			r.ChecksumsTxt += strings.Repeat("x", fleetsign.MaxChecksumsTxt)
		}), code: http.StatusBadRequest, err: "invalid_release", msg: "checksums_txt"},
		{name: "oversize sig", body: with(func(r *fleetReleaseRequest) {
			r.ChecksumsSig = base64.StdEncoding.EncodeToString(make([]byte, fleetsign.MaxChecksumsSig+1))
		}), code: http.StatusBadRequest, err: "invalid_release", msg: "checksums_sig"},
		{name: "hash mismatch", body: with(func(r *fleetReleaseRequest) {
			r.ChecksumsTxt = strings.Replace(r.ChecksumsTxt, debLine, sumB+"  imas-sprout_2.4.1_linux_amd64.deb\n", 1)
		}), code: http.StatusUnprocessableEntity, err: "checksums_mismatch", msg: "imas-sprout_2.4.1_linux_amd64.deb"},
		{name: "file not in checksums", body: with(func(r *fleetReleaseRequest) {
			r.ChecksumsTxt = strings.Replace(r.ChecksumsTxt, msiLine, "", 1)
		}), code: http.StatusUnprocessableEntity, err: "checksums_mismatch", msg: "imas-sprout-2.4.1-windows-x64.msi"},
		{name: "malformed extra line", body: with(func(r *fleetReleaseRequest) { r.ChecksumsTxt += sumT + " one-space.tar.gz\n" }),
			code: http.StatusUnprocessableEntity, err: "invalid_checksums", msg: "line 4"},
		{name: "uppercase hash on an extra line", body: with(func(r *fleetReleaseRequest) {
			r.ChecksumsTxt += strings.ToUpper(sumT) + "  other.tar.gz\n"
		}), code: http.StatusUnprocessableEntity, err: "invalid_checksums", msg: "line 4"},
		{name: "path in an extra line", body: with(func(r *fleetReleaseRequest) { r.ChecksumsTxt += sumT + "  dir/other.tar.gz\n" }),
			code: http.StatusUnprocessableEntity, err: "invalid_checksums", msg: "line 4"},
		{name: "duplicate extra file name", body: with(func(r *fleetReleaseRequest) {
			r.ChecksumsTxt += sumB + "  imas_2.4.1_linux_amd64.tar.gz\n"
		}), code: http.StatusUnprocessableEntity, err: "invalid_checksums", msg: "line 4"},
		{name: "uppercase package checksum", body: with(func(r *fleetReleaseRequest) {
			r.Packages = []fleetReleasePackage{debPkg("amd64", strings.ToUpper(sumA))}
		}), code: http.StatusUnprocessableEntity, err: "checksums_mismatch", msg: "imas-sprout_2.4.1_linux_amd64.deb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gdb, h := newOperatorTest(t)
			code, resp := register(t, h, tc.body)
			if code != tc.code {
				t.Fatalf("register = %d %v, want %d", code, resp, tc.code)
			}
			if tc.err == "" {
				return
			}
			if msg, _ := resp["message"].(string); resp["error"] != tc.err || !strings.Contains(msg, tc.msg) {
				t.Fatalf("register = %d %v, want %s naming %q", code, resp, tc.err, tc.msg)
			}
			if n := countRows(t, gdb); n != 0 {
				t.Fatalf("%d row(s) stored by a refused registration", n)
			}
		})
	}

	t.Run("replay identical", func(t *testing.T) {
		gdb, h := newOperatorTest(t)
		if code, resp := register(t, h, good); code != http.StatusCreated {
			t.Fatalf("register = %d %v", code, resp)
		}
		before := *releaseChecksums(t, gdb, "v2.4.1")
		if code, resp := register(t, h, good); code != http.StatusOK || resp["created"] != float64(0) {
			t.Fatalf("replay = %d %v, want a 200 no-op", code, resp)
		}
		if after := *releaseChecksums(t, gdb, "v2.4.1"); !after.CreatedAt.Equal(before.CreatedAt) || after.ChecksumsTxt != before.ChecksumsTxt {
			t.Fatalf("checksums row changed by a replay: %+v -> %+v", before, after)
		}
	})
	t.Run("replay different", func(t *testing.T) {
		gdb, h := newOperatorTest(t)
		if code, resp := register(t, h, good); code != http.StatusCreated {
			t.Fatalf("register = %d %v", code, resp)
		}
		for name, body := range map[string]fleetReleaseRequest{
			"different sig":       with(func(r *fleetReleaseRequest) { r.ChecksumsSig = testSig("something else") }),
			"different checksums": with(func(r *fleetReleaseRequest) { r.ChecksumsTxt += sumB + "  imas_2.4.1_extra.zip\n" }),
		} {
			if code, resp := register(t, h, body); code != http.StatusConflict || resp["error"] != "release_conflict" {
				t.Errorf("%s: %d %v, want 409 release_conflict", name, code, resp)
			}
		}
		if sums := releaseChecksums(t, gdb, "v2.4.1"); sums.ChecksumsTxt != good.ChecksumsTxt || sums.ChecksumsSig != good.ChecksumsSig {
			t.Fatalf("checksums row changed by a refused registration: %+v", sums)
		}
	})
}

// A version registered before P22 has rows but no checksums row:
// re-registering it with matching packages stores its checksums, so its
// manifest can be served, and changes no row.
func TestRegisterFleetRelease_AddsChecksumsToPreP22Version(t *testing.T) {
	gdb, h := newOperatorTest(t)
	old := FleetVersion{ID: "fv_old", Version: "v2.4.1", OS: "linux", Arch: "amd64", PackageType: "deb",
		FileName: "imas-sprout_2.4.1_linux_amd64.deb", ChecksumSHA256: sumA, MinSproutVersion: "v2.0.0",
		Signature: "v1:legacy", ReleasedAt: time.Now().UTC().Truncate(time.Second)}
	if err := gdb.Create(&old).Error; err != nil {
		t.Fatal(err)
	}
	body := releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA))
	if code, resp := register(t, h, body); code != http.StatusCreated || resp["created"] != float64(0) {
		t.Fatalf("register = %d %v, want 201 storing only the checksums", code, resp)
	}
	if sums := releaseChecksums(t, gdb, "v2.4.1"); sums == nil || sums.ChecksumsTxt != body.ChecksumsTxt {
		t.Fatalf("checksums row = %+v", sums)
	}
	if rows := releaseRows(t, gdb, "v2.4.1"); len(rows) != 1 || rows[0] != old {
		t.Fatalf("rows = %+v", rows)
	}
	if code, resp := register(t, h, body); code != http.StatusOK {
		t.Fatalf("replay = %d %v", code, resp)
	}
}

// Adding checksums to a pre-P22 version: every row already registered must
// be a line of checksums_txt with its own hash, even one the request
// doesn't name, or nothing is stored (409).
func TestRegisterFleetRelease_PreP22ChecksumsMustCoverStoredRows(t *testing.T) {
	gdb, h := newOperatorTest(t)
	for _, v := range []FleetVersion{
		{ID: "fv_deb", Version: "v2.4.1", OS: "linux", Arch: "amd64", PackageType: "deb",
			FileName: "imas-sprout_2.4.1_linux_amd64.deb", ChecksumSHA256: sumA, MinSproutVersion: "v2.0.0", ReleasedAt: time.Now()},
		{ID: "fv_msi", Version: "v2.4.1", OS: "windows", Arch: "amd64", PackageType: "msi",
			FileName: "imas-sprout-2.4.1-windows-x64.msi", ChecksumSHA256: sumC, MinSproutVersion: "v2.0.0", ReleasedAt: time.Now()},
	} {
		if err := gdb.Create(&v).Error; err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]fleetReleaseRequest{
		"stored msi not listed":        releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA)),
		"stored msi with another hash": releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA)).withSums(debPkg("amd64", sumA), msiPkg(sumB)),
	} {
		if code, resp := register(t, h, body); code != http.StatusConflict || resp["error"] != "release_conflict" ||
			!strings.Contains(resp["message"].(string), "windows/amd64/msi") {
			t.Errorf("%s: %d %v, want 409 release_conflict naming windows/amd64/msi", name, code, resp)
		}
	}
	if sums := releaseChecksums(t, gdb, "v2.4.1"); sums != nil {
		t.Fatalf("checksums stored for a version they don't cover: %+v", sums)
	}
	full := releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA)).withSums(debPkg("amd64", sumA), msiPkg(sumC))
	if code, resp := register(t, h, full); code != http.StatusCreated {
		t.Fatalf("checksums covering every stored row = %d %v, want 201", code, resp)
	}
}

// Same version, same contents: a 200 no-op, so re-running the Helm hook
// is safe.
func TestRegisterFleetRelease_SameReleaseIsNoOp(t *testing.T) {
	gdb, h := newOperatorTest(t)
	body := releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA), msiPkg(sumC))
	if code, resp := register(t, h, body); code != http.StatusCreated {
		t.Fatalf("first register = %d %v", code, resp)
	}
	before := releaseRows(t, gdb, "v2.4.1")
	for i := range 2 {
		code, resp := register(t, h, body)
		if code != http.StatusOK || resp["created"] != float64(0) || len(resp["packages"].([]any)) != 2 {
			t.Fatalf("re-register %d = %d %v", i, code, resp)
		}
	}
	// A subset of an already registered release is a no-op too.
	subset := releaseBody("v2.4.1", "v2.0.0", msiPkg(sumC)).withSums(debPkg("amd64", sumA), msiPkg(sumC))
	if code, resp := register(t, h, subset); code != http.StatusOK || resp["created"] != float64(0) {
		t.Fatalf("subset = %d %v", code, resp)
	}
	after := releaseRows(t, gdb, "v2.4.1")
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("row changed by a no-op registration:\n%+v\n%+v", before[i], after[i])
		}
	}
}

// One linux/amd64 binary ships as a .deb and an .rpm: both register as
// two rows, and re-registering either is a no-op.
func TestRegisterFleetRelease_DebAndRPMForOneOSArch(t *testing.T) {
	gdb, h := newOperatorTest(t)
	deb, rpm := debPkg("amd64", sumA), rpmPkg("amd64", sumB)
	if code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", deb, rpm)); code != http.StatusCreated || resp["created"] != float64(2) {
		t.Fatalf("register = %d %v", code, resp)
	}
	rows := releaseRows(t, gdb, "v2.4.1")
	if len(rows) != 2 || rows[0].PackageType != "deb" || rows[1].PackageType != "rpm" {
		t.Fatalf("rows = %+v", rows)
	}
	if code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", rpm).withSums(deb, rpm)); code != http.StatusOK || resp["created"] != float64(0) {
		t.Fatalf("re-register rpm = %d %v", code, resp)
	}
	changed := rpmPkg("amd64", sumC)
	if code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", changed).withSums(deb, changed)); code != http.StatusConflict {
		t.Fatalf("rpm with another checksum = %d %v, want 409", code, resp)
	}
}

// Same version with different contents is 409, and nothing changes.
func TestRegisterFleetRelease_ConflictIs409(t *testing.T) {
	gdb, h := newOperatorTest(t)
	all := []fleetReleasePackage{debPkg("amd64", sumA), msiPkg(sumC)}
	if code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA)).withSums(all...)); code != http.StatusCreated {
		t.Fatalf("register = %d %v", code, resp)
	}
	before := releaseRows(t, gdb, "v2.4.1")

	renamed := debPkg("amd64", sumA)
	renamed.FileName = "imas-sprout_2.4.1-1_linux_amd64.deb"
	for name, body := range map[string]fleetReleaseRequest{
		"different checksum":           releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumB)),
		"different checksum, plus new": releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumB), msiPkg(sumC)),
		"different file_name":          releaseBody("v2.4.1", "v2.0.0", renamed).withSums(renamed, msiPkg(sumC)),
		"different min_sprout_version": releaseBody("v2.4.1", "v1.0.0", debPkg("amd64", sumA)).withSums(all...),
		"new package, different floor": releaseBody("v2.4.1", "v1.0.0", msiPkg(sumC)).withSums(all...),
	} {
		code, resp := register(t, h, body)
		if code != http.StatusConflict || resp["error"] != "release_conflict" {
			t.Errorf("%s: %d %v, want 409 release_conflict", name, code, resp)
		}
	}
	after := releaseRows(t, gdb, "v2.4.1")
	if len(after) != 1 || after[0] != before[0] {
		t.Fatalf("rows changed by a refused registration: %+v", after)
	}
}

// A package for an OS/arch the version doesn't have yet is added, with
// the version's existing release time, as long as checksums.txt is the
// same file.
func TestRegisterFleetRelease_AddsPackageToVersion(t *testing.T) {
	gdb, h := newOperatorTest(t)
	all := []fleetReleasePackage{debPkg("amd64", sumA), msiPkg(sumC)}
	if code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA)).withSums(all...)); code != http.StatusCreated {
		t.Fatalf("register = %d %v", code, resp)
	}
	first := releaseRows(t, gdb, "v2.4.1")[0]
	code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", all...))
	if code != http.StatusCreated || resp["created"] != float64(1) || len(resp["packages"].([]any)) != 2 {
		t.Fatalf("register with a new package = %d %v", code, resp)
	}
	rows := releaseRows(t, gdb, "v2.4.1")
	if rows[0] != first || !rows[1].ReleasedAt.Equal(first.ReleasedAt) || rows[1].OS != "windows" {
		t.Fatalf("rows = %+v", rows)
	}
}

func TestRegisterFleetRelease_Validation(t *testing.T) {
	gdb, h := newOperatorTest(t)
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
	const sums = `,"checksums_txt":"x","checksums_sig":"eA=="`
	cases := map[string]any{
		"not JSON":              "nope",
		"array":                 "[]",
		"unknown field":         `{"version":"v2.4.1","channel":"stable","min_sprout_version":"v2.0.0","packages":[]` + sums + `,"artifact_url":"https://evil.test/x"}`,
		"unknown package field": `{"version":"v2.4.1","channel":"stable","min_sprout_version":"v2.0.0","packages":[{"os":"linux","arch":"amd64","package_type":"deb","file_name":"a.deb","checksum_sha256":"` + sumA + `","signature":"v1:x"}]` + sums + `}`,
		"trailing data":         `{"version":"v2.4.1","channel":"stable","min_sprout_version":"v2.0.0","packages":[]` + sums + `} {}`,
		"no packages":           with(func(r *fleetReleaseRequest) { r.Packages = nil }),
		"too many packages":     with(func(r *fleetReleaseRequest) { r.Packages = many }),
		"no channel":            with(func(r *fleetReleaseRequest) { r.Channel = "" }),
		"bad channel":           with(func(r *fleetReleaseRequest) { r.Channel = "Stable Channel" }),
		"no version":            with(func(r *fleetReleaseRequest) { r.Version = "" }),
		"non-canonical version": with(func(r *fleetReleaseRequest) { r.Version = "2.4.1" }),
		"min above version":     with(func(r *fleetReleaseRequest) { r.MinSproutVersion = "v3.0.0" }),
		"uppercase os":          pkg(func(p *fleetReleasePackage) { p.OS = "Linux" }),
		"unknown package_type":  pkg(func(p *fleetReleasePackage) { p.PackageType = "apk"; p.FileName = "imas-sprout.apk" }),
		"msi on linux":          pkg(func(p *fleetReleasePackage) { p.PackageType = "msi"; p.FileName = "imas-sprout.msi" }),
		"deb on windows":        pkg(func(p *fleetReleasePackage) { p.OS = "windows" }),
		"file_name not .deb":    pkg(func(p *fleetReleasePackage) { p.FileName = "imas-sprout_2.4.1_amd64.rpm" }),
		"darwin":                pkg(func(p *fleetReleasePackage) { p.OS = "darwin" }),
		"duplicate os/arch/type": with(func(r *fleetReleaseRequest) {
			r.Packages = append(r.Packages, debPkg("amd64", sumB))
		}),
		"duplicate, same pkg": with(func(r *fleetReleaseRequest) { r.Packages = append(r.Packages, r.Packages[0]) }),
	}
	for name, body := range cases {
		code, resp := register(t, h, body)
		if code != http.StatusBadRequest || (resp["error"] != "invalid_request" && resp["error"] != "invalid_release") {
			t.Errorf("%s: %d %v, want 400", name, code, resp)
		}
	}
	// A file name or checksum that can't be a checksums.txt line is never
	// in checksums_txt: 422, naming the file.
	for name, body := range map[string]fleetReleaseRequest{
		"short checksum":    pkg(func(p *fleetReleasePackage) { p.ChecksumSHA256 = "abc" }),
		"path in file_name": pkg(func(p *fleetReleasePackage) { p.FileName = "pool/main/imas-sprout.deb" }),
		"dot-dot file_name": pkg(func(p *fleetReleasePackage) { p.FileName = "../imas-sprout.deb" }),
		"url as file_name":  pkg(func(p *fleetReleasePackage) { p.FileName = "https://evil.test/imas-sprout.deb" }),
	} {
		code, resp := register(t, h, body)
		if code != http.StatusUnprocessableEntity || resp["error"] != "checksums_mismatch" {
			t.Errorf("%s: %d %v, want 422 checksums_mismatch", name, code, resp)
		}
	}
	if countRows(t, gdb) != 0 {
		t.Fatalf("invalid releases: %d row(s)", countRows(t, gdb))
	}
	if code, _ := register(t, h, strings.Repeat(" ", maxReleaseRequestBytes+1)+"{}"); code != http.StatusBadRequest {
		t.Fatalf("oversized body: %d", code)
	}
	// A body carrying checksums.txt at its limit fits.
	big := valid
	big.ChecksumsTxt += strings.Repeat(sumT+"  imas-filler.tar.gz\n", 1)
	for len(big.ChecksumsTxt)+90 <= fleetsign.MaxChecksumsTxt {
		big.ChecksumsTxt += sumT + "  imas-filler-" + strings.Repeat("x", 8) + "-" + string(rune('a'+len(big.ChecksumsTxt)%26)) + ".tar.gz\n"
	}
	data, _ := json.Marshal(big)
	if len(data) > maxReleaseRequestBytes {
		t.Fatalf("a %d-byte checksums_txt makes a %d-byte body, over maxReleaseRequestBytes", len(big.ChecksumsTxt), len(data))
	}
}

func TestRevokeFleetRelease(t *testing.T) {
	gdb, h := newOperatorTest(t)
	all := []fleetReleasePackage{debPkg("amd64", sumA), msiPkg(sumC), debPkg("arm64", sumB)}
	body := releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA), msiPkg(sumC)).withSums(all...)
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
	if code, resp := register(t, h, releaseBody("v2.4.1", "v2.0.0", debPkg("arm64", sumB)).withSums(all...)); code != http.StatusConflict || resp["error"] != "version_revoked" {
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
	p := &operatorPlane{tokens: [][]byte{[]byte(testOperatorToken)}}
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
// secret, not an end-user JWT, not some other service's token. And the
// two planes don't share routes.
func TestOperatorPlaneAuth(t *testing.T) {
	gdb, h := newOperatorTest(t)
	auth := newTestAuthEnv(t)
	body, _ := json.Marshal(releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA)))

	for name, set := range map[string]func(r *http.Request){
		"no credentials":       func(*http.Request) {},
		"BFF secret and JWT":   func(r *http.Request) { auth.setAuthHeaders(r, "t_x") },
		"BFF secret as bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+testInternalAuthSecretCurrent) },
		"another token":        func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+testOtherToken) },
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
	if countRows(t, gdb) != 0 {
		t.Fatalf("unauthenticated requests: %d row(s)", countRows(t, gdb))
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

func writeSecret(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
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
		"off":                  with(func(c *Config) { c.OperatorListenAddr = "" }),
		"no cert":              with(func(c *Config) { c.OperatorTLSCertFile = "" }),
		"unreadable cert":      with(func(c *Config) { c.OperatorTLSCertFile = filepath.Join(t.TempDir(), "x") }),
		"no operator token":    with(func(c *Config) { c.OperatorTokenFile = "" }),
		"short operator token": with(func(c *Config) { c.OperatorTokenFile = writeSecret(t, "short") }),
		"bad previous token":   with(func(c *Config) { c.OperatorTokenPreviousFile = writeSecret(t, "short") }),
		"operator token is BFF's": with(func(c *Config) {
			c.OperatorTokenFile = writeSecret(t, testInternalAuthSecretCurrent+"-padded-to-length")
			c.InternalAuthSecretCurrent = testInternalAuthSecretCurrent + "-padded-to-length"
		}),
		"previous is BFF's previous": with(func(c *Config) {
			c.InternalAuthSecretPrevious = testOperatorTokenPrevious
			c.OperatorTokenPreviousFile = writeSecret(t, testOperatorTokenPrevious)
		}),
	} {
		if _, err := NewOperatorServer(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadConfigOperatorPlane(t *testing.T) {
	set := map[string]string{
		"SAASAPI_OPERATOR_LISTEN_ADDR":   ":8443",
		"SAASAPI_OPERATOR_TLS_CERT_FILE": "/tls/tls.crt",
		"SAASAPI_OPERATOR_TLS_KEY_FILE":  "/tls/tls.key",
		"SAASAPI_OPERATOR_TOKEN_FILE":    "/op/token",
	}
	for k, v := range set {
		t.Setenv(k, v)
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OperatorListenAddr != ":8443" || cfg.OperatorTokenFile != "/op/token" {
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
	// Off: nothing else is required.
	for k := range set {
		t.Setenv(k, "")
	}
	if cfg, err := LoadConfig(); err != nil || cfg.OperatorListenAddr != "" {
		t.Fatalf("operator plane off: %+v, %v", cfg, err)
	}
}
