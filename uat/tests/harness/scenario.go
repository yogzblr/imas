package harness

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// Scenario carries what every failure message names: the scenario id,
// the OS, the tenant, the VM and the current step. Its methods prefix
// messages with "[<id> os=<os> tenant=<n> vm=<vm> step=<step>]", then
// "FAIL: " on Fatalf and Errorf and "SKIP: " on Skipf, which
// uat/tests/uatreport picks out as the failure's detail or the skip's
// reason.
//
// A Scenario belongs to one test; derive one per subtest with ForSprout or
// ForTenant.
type Scenario struct {
	T      testing.TB
	ID     string
	OS     string
	Tenant int
	VM     string

	mu   sync.Mutex
	step string
}

// Begin starts a scenario in a top-level test.
func Begin(t testing.TB, id string) *Scenario { return &Scenario{T: t, ID: id} }

// ForSprout derives the scenario for a sprout's subtest.
func (s *Scenario) ForSprout(t testing.TB, sp Sprout) *Scenario {
	return &Scenario{T: t, ID: s.ID, OS: sp.OS, Tenant: sp.Tenant, VM: sp.VM, step: s.Step0()}
}

// ForTenant derives the scenario for a tenant's subtest.
func (s *Scenario) ForTenant(t testing.TB, n int) *Scenario {
	return &Scenario{T: t, ID: s.ID, OS: s.OS, Tenant: n, VM: s.VM, step: s.Step0()}
}

// Step records what the test is doing now, and logs it.
func (s *Scenario) Step(format string, args ...any) {
	s.T.Helper()
	s.mu.Lock()
	s.step = fmt.Sprintf(format, args...)
	s.mu.Unlock()
	s.T.Logf("%s", s.Where())
}

// Step0 is the current step.
func (s *Scenario) Step0() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.step
}

// Where is the message prefix.
func (s *Scenario) Where() string {
	var b strings.Builder
	b.WriteString("[" + s.ID)
	if s.OS != "" {
		b.WriteString(" os=" + s.OS)
	}
	if s.Tenant != 0 {
		fmt.Fprintf(&b, " tenant=%d", s.Tenant)
	}
	if s.VM != "" {
		b.WriteString(" vm=" + s.VM)
	}
	if st := s.Step0(); st != "" {
		b.WriteString(" step=" + st)
	}
	b.WriteString("]")
	return b.String()
}

// Fatalf fails the test now.
func (s *Scenario) Fatalf(format string, args ...any) {
	s.T.Helper()
	s.T.Fatalf("%s FAIL: %s", s.Where(), fmt.Sprintf(format, args...))
}

// Errorf fails the test and goes on.
func (s *Scenario) Errorf(format string, args ...any) {
	s.T.Helper()
	s.T.Errorf("%s FAIL: %s", s.Where(), fmt.Sprintf(format, args...))
}

// Logf logs with the prefix.
func (s *Scenario) Logf(format string, args ...any) {
	s.T.Helper()
	s.T.Logf("%s %s", s.Where(), fmt.Sprintf(format, args...))
}

// Skipf skips the test with a written reason. The no silent green rule
// of run.sh counts a skip only when it has one.
func (s *Scenario) Skipf(format string, args ...any) {
	s.T.Helper()
	s.T.Skipf("%s SKIP: %s", s.Where(), fmt.Sprintf(format, args...))
}

// NoErr fails the test now if err is set.
func (s *Scenario) NoErr(err error, what string, args ...any) {
	s.T.Helper()
	if err != nil {
		s.Fatalf("%s: %v", fmt.Sprintf(what, args...), err)
	}
}

// Expect fails the test now unless the response has the status and, if
// code isn't empty, the error code. It fails on a transport error too.
func (s *Scenario) Expect(r *Response, err error, status int, code string, what string, args ...any) {
	s.T.Helper()
	w := fmt.Sprintf(what, args...)
	if err != nil {
		s.Fatalf("%s: %v", w, err)
	}
	if !r.Is(status, code) {
		want := fmt.Sprintf("HTTP %d", status)
		if code != "" {
			want += " " + code
		}
		s.Fatalf("%s: want %s, got %s", w, want, r)
	}
}

// Check is Expect that goes on after a mismatch, and reports whether the
// response matched.
func (s *Scenario) Check(r *Response, err error, status int, code string, what string, args ...any) bool {
	s.T.Helper()
	w := fmt.Sprintf(what, args...)
	if err != nil {
		s.Errorf("%s: %v", w, err)
		return false
	}
	if !r.Is(status, code) {
		want := fmt.Sprintf("HTTP %d", status)
		if code != "" {
			want += " " + code
		}
		s.Errorf("%s: want %s, got %s", w, want, r)
		return false
	}
	return true
}

// ExpectItem fails the test now unless the batch has the sprout's item in
// the given status and, if code isn't empty, with that error code.
func (s *Scenario) ExpectItem(b *Batch, sp Sprout, status, code string) Item {
	s.T.Helper()
	it, ok := b.For(sp)
	if !ok {
		s.Fatalf("the batch has no item for asset %s: %s", sp.AssetID, describeItems(b))
	}
	if it.Status != status || (code != "" && it.Error != code) {
		want := status
		if code != "" {
			want += " " + code
		}
		s.Fatalf("want item %s, got %s", want, it)
	}
	return it
}

// NotFoundOrForbidden reports whether a response is a 403, or the plain
// ServeMux 404 of a route that isn't registered (the flag-gated update
// routes): both mean the call was refused before any handler ran.
func NotFoundOrForbidden(r *Response) bool {
	if r == nil {
		return false
	}
	return r.Status == http.StatusForbidden || (r.Status == http.StatusNotFound && r.Error.Code == "")
}
