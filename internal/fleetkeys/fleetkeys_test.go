package fleetkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/fleetsign"
)

type staticKeys struct {
	ks  fleetsign.KeySet
	err error
}

func (s staticKeys) KeySet(context.Context) (fleetsign.KeySet, error) { return s.ks, s.err }

func startBus(t *testing.T) *nats.Conn {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats-server not ready")
	}
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func twoVersions(t *testing.T) fleetsign.KeySet {
	t.Helper()
	var keys []fleetsign.PublicKey
	for v := 1; v <= 2; v++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		keys = append(keys, fleetsign.PublicKey{Version: v, Key: pub})
	}
	ks, err := fleetsign.NewKeySet(keys)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func TestFetch_RoundTripThroughFarmerListener(t *testing.T) {
	nc := startBus(t)
	ks := twoVersions(t)
	SetKeySource(staticKeys{ks: ks})
	t.Cleanup(func() { SetKeySource(nil) })
	if err := RegisterFarmerListener("t_1", nc); err != nil {
		t.Fatal(err)
	}

	got, err := Fetch(t.Context(), nc, "web-01")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// Every version, ascending — the PublicKeys shape, not just the newest.
	if len(got) != 2 || got[0].Version != 1 || got[1].Version != 2 ||
		!got[0].Key.Equal(ks[0].Key) || !got[1].Key.Equal(ks[1].Key) {
		t.Fatalf("Fetch = %+v, want %+v", got, ks)
	}
}

func TestFetch_FarmerCannotReadKeys(t *testing.T) {
	nc := startBus(t)
	if err := RegisterFarmerListener("t_1", nc); err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]fleetsign.KeySetSource{
		"no key source":      nil,
		"Transit refuses it": staticKeys{err: errors.New("403 permission denied: /var/secret/path")},
	} {
		SetKeySource(src)
		_, err := Fetch(t.Context(), nc, "web-01")
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: Fetch = %v, want ErrUnavailable", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "/var/secret") {
			t.Errorf("%s: farmer's error text reached the sprout: %v", name, err)
		}
	}
	SetKeySource(nil)
}

// A reply that isn't a usable key set is an error, never an empty trust
// set that would make every signature "unknown version" silently.
func TestFetch_RejectsMalformedReplies(t *testing.T) {
	nc := startBus(t)
	for name, reply := range map[string]string{
		"not json":       `{`,
		"no keys":        `{"keys":[]}`,
		"short key":      `{"keys":[{"version":1,"public_key":"AAAA"}]}`,
		"version 0":      `{"keys":[{"version":0,"public_key":"` + b64Key(t) + `"}]}`,
		"duplicate kver": `{"keys":[{"version":1,"public_key":"` + b64Key(t) + `"},{"version":1,"public_key":"` + b64Key(t) + `"}]}`,
	} {
		sub, err := nc.Subscribe(SproutSubject("web-01"), func(m *nats.Msg) { _ = m.Respond([]byte(reply)) })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Fetch(t.Context(), nc, "web-01"); err == nil {
			t.Errorf("%s: Fetch accepted %s", name, reply)
		}
		sub.Unsubscribe()
	}
}

func TestFetch_NoResponderIsAnError(t *testing.T) {
	nc := startBus(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := Fetch(ctx, nc, "web-01"); err == nil {
		t.Fatal("Fetch with nobody answering succeeded")
	}
	if _, err := Fetch(ctx, nil, "web-01"); err == nil {
		t.Fatal("Fetch with no connection succeeded")
	}
}

func b64Key(t *testing.T) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return base64.StdEncoding.EncodeToString(pub)
}

// Farmer answers only on the requesting sprout's own reply subjects: a
// sprout naming another sprout's subject (or a wildcard, or _INBOX) as
// its reply gets no answer, so it can't make farmer publish there.
func TestFarmerRefusesForeignReplySubjects(t *testing.T) {
	nc := startBus(t)
	SetKeySource(staticKeys{ks: twoVersions(t)})
	t.Cleanup(func() { SetKeySource(nil) })
	if err := RegisterFarmerListener("t_1", nc); err != nil {
		t.Fatal(err)
	}
	for _, reply := range []string{
		"imas.sprouts.web-02.cmd.run",
		"imas.sprouts.web-02.fleetsigningkeys.reply.x",
		"imas.sprouts.web-01.fleetsigningkeys.reply",
		"imas.sprouts.web-01.fleetsigningkeys.reply.a.b",
		"imas.sprouts.web-01.fleetsigningkeys.reply.*",
		"_INBOX.abc",
	} {
		sub, _ := nc.SubscribeSync(reply)
		if strings.ContainsAny(reply, "*") {
			sub, _ = nc.SubscribeSync("imas.sprouts.web-01.fleetsigningkeys.reply.>")
		}
		if err := nc.PublishRequest(SproutSubject("web-01"), reply, nil); err != nil {
			t.Fatal(err)
		}
		if msg, err := sub.NextMsg(200 * time.Millisecond); err == nil {
			t.Errorf("farmer answered on %q: %s", reply, msg.Data)
		}
		sub.Unsubscribe()
	}
	// The legitimate shape still works.
	if _, err := Fetch(t.Context(), nc, "web-01"); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
}

func TestValidReplySubject(t *testing.T) {
	if !validReplySubject("web-01", ReplyPrefix("web-01")+".abc123") {
		t.Error("own reply subject refused")
	}
	for _, r := range []string{"", ReplyPrefix("web-01"), ReplyPrefix("web-01") + ".", ReplyPrefix("web-01") + ".a b",
		ReplyPrefix("web-01") + ".>", ReplyPrefix("web-02") + ".abc", ReplyPrefix("web-01") + "." + strings.Repeat("a", 300)} {
		if validReplySubject("web-01", r) {
			t.Errorf("accepted %q", r)
		}
	}
}
