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

func TestRefreshStaleUserJWT(t *testing.T) {
	account, _ := nkeys.CreateAccount()
	user, _ := nkeys.CreateUser()
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
	stale := mint("imas.sprouts.web-01.facts")
	fresh := mint(pki.SproutHeartbeatSubject("web-01"))

	run := func(userJWT string, loadErr, refreshErr error) (made bool, calls int) {
		made = refreshStaleUserJWT(context.Background(), "web-01",
			func() (string, error) { return userJWT, loadErr },
			func(context.Context) (string, error) { calls++; return "web-01", refreshErr })
		return made, calls
	}

	if made, calls := run(stale, nil, nil); !made || calls != 1 {
		t.Errorf("stale JWT: made=%v calls=%d, want one successful refresh", made, calls)
	}
	if made, calls := run(fresh, nil, nil); made || calls != 0 {
		t.Errorf("JWT with the grant: made=%v calls=%d, want no refresh", made, calls)
	}
	if made, calls := run("", os.ErrNotExist, nil); made || calls != 0 {
		t.Errorf("no JWT on disk: made=%v calls=%d, want no refresh", made, calls)
	}
	if made, calls := run(stale, nil, errors.New("farmer unreachable")); made || calls != 1 {
		t.Errorf("failing refresh: made=%v calls=%d, want one attempt reported as not made", made, calls)
	}
}
