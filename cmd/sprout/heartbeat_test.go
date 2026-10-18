package main

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/pki"
)

func TestHeartbeatPermitted(t *testing.T) {
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	userPub, _ := user.PublicKey()
	mint := func(allow ...string) string {
		uc := jwt.NewUserClaims(userPub)
		uc.Pub.Allow.Add(allow...)
		s, err := uc.Encode(account)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	if !heartbeatPermitted(mint(pki.SproutHeartbeatSubject("web-01")), "web-01") {
		t.Error("own heartbeat grant not found")
	}
	if heartbeatPermitted(mint(pki.SproutHeartbeatSubject("web-02")), "web-01") {
		t.Error("another sprout's heartbeat grant counted as this sprout's")
	}
	if heartbeatPermitted(mint("imas.sprouts.web-01.facts"), "web-01") {
		t.Error("permitted without a heartbeat grant (JWT minted before it existed)")
	}
	if heartbeatPermitted("not a jwt", "web-01") {
		t.Error("permitted with an unparsable JWT")
	}
	if !heartbeatPermitted("", "web-01") {
		t.Error("a connection with no User JWT has no per-subject permissions to lack")
	}
}

// UAT.13, the full grant: a JWT is stale unless it carries exactly
// pki.SproutPermissions, so a JWT with the heartbeat grant but without a
// later one (logs, box key, shell) is refreshed too.
func TestRefreshStaleUserJWT(t *testing.T) {
	account, _ := nkeys.CreateAccount()
	user, _ := nkeys.CreateUser()
	userPub, _ := user.PublicKey()
	mint := func(p jwt.Permissions) string {
		uc := jwt.NewUserClaims(userPub)
		uc.Permissions = p
		s, err := uc.Encode(account)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	full := pki.SproutPermissions("web-01")
	noHeartbeat := pki.SproutPermissions("web-01")
	noHeartbeat.Pub.Allow.Remove(pki.SproutHeartbeatSubject("web-01"))
	noShell := pki.SproutPermissions("web-01")
	noShell.Pub.Allow.Remove(pki.SproutShellPublishGrant("web-01"))
	noBoxKey := pki.SproutPermissions("web-01")
	noBoxKey.Pub.Allow.Remove(pki.SproutBoxKeySubmitSubject("web-01"))
	heartbeatOnly := jwt.Permissions{Pub: jwt.Permission{Allow: jwt.StringList{pki.SproutHeartbeatSubject("web-01")}}}

	run := func(userJWT string, loadErr, refreshErr error) (made bool, calls int) {
		made = refreshStaleUserJWT(context.Background(), "web-01",
			func() (string, error) { return userJWT, loadErr },
			func(context.Context) (string, error) { calls++; return "web-01", refreshErr })
		return made, calls
	}

	for name, p := range map[string]jwt.Permissions{
		"no heartbeat grant":       noHeartbeat,
		"no shell grant":           noShell,
		"no box key grant":         noBoxKey,
		"only the heartbeat grant": heartbeatOnly,
		"another sprout's grant":   pki.SproutPermissions("web-02"),
	} {
		if made, calls := run(mint(p), nil, nil); !made || calls != 1 {
			t.Errorf("%s: made=%v calls=%d, want one successful refresh", name, made, calls)
		}
	}
	if made, calls := run(mint(full), nil, nil); made || calls != 0 {
		t.Errorf("JWT with the full grant: made=%v calls=%d, want no refresh", made, calls)
	}
	if made, calls := run("", os.ErrNotExist, nil); made || calls != 0 {
		t.Errorf("no JWT on disk: made=%v calls=%d, want no refresh", made, calls)
	}
	if made, calls := run(mint(noHeartbeat), nil, errors.New("farmer unreachable")); made || calls != 1 {
		t.Errorf("failing refresh: made=%v calls=%d, want one attempt reported as not made", made, calls)
	}
}

// fakeBus is a sproutBus whose persisted JWT the test sets.
type fakeBus struct {
	inUse, onDisk string
	err           error
}

func (b *fakeBus) UserJWT() string { return b.inUse }

func (b *fakeBus) ReloadUserJWT() (bool, error) {
	if b.err != nil || b.onDisk == b.inUse {
		return false, b.err
	}
	b.inUse = b.onDisk
	return true, nil
}

type fakeReconnecter struct{ n int }

func (r *fakeReconnecter) ForceReconnect() error { r.n++; return nil }

// The heartbeat gate reconnects with a JWT a refresh changed, at the next
// tick, without a restart: that tick does not publish, the grants are
// re-applied for the new JWT, and later ticks publish once it carries the
// heartbeat grant.
func TestHeartbeatGate(t *testing.T) {
	account, _ := nkeys.CreateAccount()
	user, _ := nkeys.CreateUser()
	userPub, _ := user.PublicKey()
	mint := func(p jwt.Permissions) string {
		uc := jwt.NewUserClaims(userPub)
		uc.Permissions = p
		s, err := uc.Encode(account)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	old := pki.SproutPermissions("web-01")
	old.Pub.Allow.Remove(pki.SproutHeartbeatSubject("web-01"))
	stale, fresh := mint(old), mint(pki.SproutPermissions("web-01"))

	bus := &fakeBus{inUse: stale, onDisk: stale}
	var rc fakeReconnecter
	var applied []string
	gate := heartbeatGate(bus, &rc, "web-01", func(j string) { applied = append(applied, j) })

	for i := range 3 {
		if gate() {
			t.Fatalf("tick %d: publishes with a JWT that has no heartbeat grant", i)
		}
	}
	if rc.n != 0 || len(applied) != 0 {
		t.Fatalf("reconnected %d times, re-applied %v, with the JWT unchanged", rc.n, applied)
	}

	bus.onDisk = fresh // a refresh wrote the re-minted JWT
	if gate() {
		t.Fatal("the switching tick publishes on the old connection")
	}
	if rc.n != 1 || len(applied) != 1 || applied[0] != fresh {
		t.Fatalf("after a refresh: reconnects %d, re-applied %d (want 1 and 1, with the new JWT)", rc.n, len(applied))
	}
	for i := range 3 {
		if !gate() {
			t.Fatalf("tick %d after the switch: no heartbeat with the re-minted JWT", i)
		}
	}
	if rc.n != 1 {
		t.Fatalf("reconnected %d times; once per change", rc.n)
	}

	// A file that cannot be read keeps the JWT in use.
	bus.err = errors.New("unreadable")
	if !gate() || rc.n != 1 {
		t.Fatal("an unreadable JWT file stopped the heartbeat or reconnected")
	}
}
