package main

import (
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
