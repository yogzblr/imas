package fleetkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
)

type staticKeys struct {
	ks  fleetsign.KeySet
	err error
}

func (s staticKeys) KeySet(context.Context) (fleetsign.KeySet, error) { return s.ks, s.err }

// startBus starts an embedded NATS server and returns a connection to
// it. It also gives farmer an empty box-key database and the sprout no
// payload-encryption keys: the pre-workstream-J setup, on both ends,
// until readySprout says otherwise.
func startBus(t *testing.T) *nats.Conn {
	t.Helper()
	setupPKIDB(t)
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

// --- sealed replies ---

func setupPKIDB(t *testing.T) {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open("file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(pki.Models()...); err != nil {
		t.Fatal(err)
	}
	pki.SetDB(gdb)
	t.Cleanup(func() {
		if sqlDB, err := gdb.DB(); err == nil {
			sqlDB.Close()
		}
	})
	origGrace, origPriv, origPin := config.BoxKeyGraceDuration, config.SproutBoxPrivFile, config.SproutTenantX25519PubFile
	t.Cleanup(func() {
		config.BoxKeyGraceDuration, config.SproutBoxPrivFile, config.SproutTenantX25519PubFile = origGrace, origPriv, origPin
	})
	config.BoxKeyGraceDuration = time.Hour
	config.SproutBoxPrivFile, config.SproutTenantX25519PubFile = "", ""
}

// readySprout gives sproutID of tenant everything workstream J enrolls:
// a box keypair on the sprout's disk with its public half on record
// farmer-side, and the tenant's box public key (from a mock OpenBao)
// pinned sprout-side. Call after startBus.
func readySprout(t *testing.T, tenant, sproutID string) *tenantboxtest.Server {
	t.Helper()
	dir := t.TempDir()
	kv := tenantboxtest.Start(t)
	pki.InvalidateTenantBoxKeys(tenant)
	t.Cleanup(func() { pki.InvalidateTenantBoxKeys(tenant) })
	config.SproutBoxPrivFile = filepath.Join(dir, "box.key")
	config.SproutTenantX25519PubFile = filepath.Join(dir, "tenant-x25519.pub")

	sproutPub, err := pki.EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.RotateSproutBoxKey(tenant, sproutID, sproutPub, time.Hour); err != nil {
		t.Fatal(err)
	}
	tenantPub, err := pki.GetTenantX25519PublicKey(tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.SproutTenantX25519PubFile, []byte(tenantPub), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pki.SproutBoxReady() {
		t.Fatal("sprout isn't box-ready after setup")
	}
	return kv
}

func useKeys(t *testing.T, ks fleetsign.KeySet) {
	t.Helper()
	SetKeySource(staticKeys{ks: ks})
	t.Cleanup(func() { SetKeySource(nil) })
}

// rawRequest sends body as sproutID's request, the way Fetch does, and
// returns whatever arrives on the reply subject.
func rawRequest(t *testing.T, nc *nats.Conn, sproutID string, body []byte) *nats.Msg {
	t.Helper()
	reply := ReplyPrefix(sproutID) + ".raw"
	sub, err := nc.SubscribeSync(reply)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	if err := nc.PublishRequest(SproutSubject(sproutID), reply, body); err != nil {
		t.Fatal(err)
	}
	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("no reply: %v", err)
	}
	return msg
}

func requestBody(t *testing.T, id string) []byte {
	t.Helper()
	b, err := json.Marshal(Request{ID: id})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFetch_SealedRoundTrip(t *testing.T) {
	nc := startBus(t)
	readySprout(t, "t_1", "web-01")
	ks := twoVersions(t)
	useKeys(t, ks)
	if err := RegisterFarmerListener("t_1", nc); err != nil {
		t.Fatal(err)
	}

	// What the bus sees: a sealed reply, not a Response.
	spy, err := nc.SubscribeSync(ReplyPrefix("web-01") + ".>")
	if err != nil {
		t.Fatal(err)
	}
	defer spy.Unsubscribe()

	got, err := Fetch(t.Context(), nc, "web-01")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 2 || !got[0].Key.Equal(ks[0].Key) || !got[1].Key.Equal(ks[1].Key) {
		t.Fatalf("Fetch = %+v, want %+v", got, ks)
	}
	seen, err := spy.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("bus saw no reply: %v", err)
	}
	if seen.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		t.Errorf("reply isn't marked sealed: %v", seen.Header)
	}
	var plain Response
	if json.Unmarshal(seen.Data, &plain) == nil && len(plain.Keys) != 0 {
		t.Errorf("reply decodes as a plaintext Response: %s", seen.Data)
	}

	// Farmer's own report of a key source failure is sealed too, so a
	// box-ready sprout sees ErrUnavailable, not a downgrade refusal.
	SetKeySource(staticKeys{err: errors.New("transit down")})
	if _, err := Fetch(t.Context(), nc, "web-01"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Fetch with the key source failing = %v, want ErrUnavailable", err)
	}
}

// Farmer, pre-J sprout: no box key on record means plaintext, as before.
// Pre-J sprout: no keys of its own means it accepts plaintext.
func TestFetch_PreJSproutGetsAndAcceptsPlaintext(t *testing.T) {
	nc := startBus(t)
	ks := twoVersions(t)
	useKeys(t, ks)
	if err := RegisterFarmerListener("t_1", nc); err != nil {
		t.Fatal(err)
	}

	id, _ := payloadbox.NewID()
	msg := rawRequest(t, nc, "web-01", requestBody(t, id))
	if len(msg.Header.Values(payloadbox.Header)) != 0 {
		t.Fatalf("farmer sealed a reply to a sprout with no box key: %v", msg.Header)
	}
	var resp Response
	if err := json.Unmarshal(msg.Data, &resp); err != nil || len(resp.Keys) != 2 {
		t.Fatalf("plaintext reply = %s (%v)", msg.Data, err)
	}

	got, err := Fetch(t.Context(), nc, "web-01")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Fetch = %+v", got)
	}
}

// A sprout that doesn't send a request id (built before sealed replies)
// can't open a sealed reply, so farmer answers it in plaintext even if it
// has a box key on record — otherwise it could never self-update to a
// build that can.
func TestFarmer_RequestWithoutIDGetsPlaintext(t *testing.T) {
	nc := startBus(t)
	readySprout(t, "t_1", "web-01")
	useKeys(t, twoVersions(t))
	if err := RegisterFarmerListener("t_1", nc); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{"no body": nil, "no id": []byte(`{}`)} {
		msg := rawRequest(t, nc, "web-01", body)
		var resp Response
		if len(msg.Header.Values(payloadbox.Header)) != 0 || json.Unmarshal(msg.Data, &resp) != nil || len(resp.Keys) != 2 {
			t.Errorf("%s: reply %v %s, want plaintext keys", name, msg.Header, msg.Data)
		}
	}
}

// A request id that isn't payloadbox.NewID's shape gets no answer.
func TestFarmer_DropsMalformedRequests(t *testing.T) {
	nc := startBus(t)
	readySprout(t, "t_1", "web-01")
	useKeys(t, twoVersions(t))
	if err := RegisterFarmerListener("t_1", nc); err != nil {
		t.Fatal(err)
	}
	reply := ReplyPrefix("web-01") + ".raw"
	sub, _ := nc.SubscribeSync(reply)
	defer sub.Unsubscribe()
	for _, body := range []string{`{`, `{"id":"short"}`, `{"id":"` + strings.Repeat("A", 32) + `"}`, `{"id":"` + strings.Repeat("a", 33) + `"}`, `{"id":1}`} {
		if err := nc.PublishRequest(SproutSubject("web-01"), reply, []byte(body)); err != nil {
			t.Fatal(err)
		}
		if msg, err := sub.NextMsg(200 * time.Millisecond); err == nil {
			t.Errorf("farmer answered %s: %v %s", body, msg.Header, msg.Data)
		}
	}
}

// Failing to seal for any reason but "no box key on record" is
// errorUnavailable, never the keys in plaintext.
func TestFarmer_SealFailureIsUnavailableNotPlaintext(t *testing.T) {
	nc := startBus(t)
	kv := readySprout(t, "t_1", "web-01")
	useKeys(t, twoVersions(t))
	if err := RegisterFarmerListener("t_1", nc); err != nil {
		t.Fatal(err)
	}
	// OpenBao goes away, and the cached tenant key set with it.
	kv.Close()
	pki.InvalidateTenantBoxKeys("t_1")

	id, _ := payloadbox.NewID()
	msg := rawRequest(t, nc, "web-01", requestBody(t, id))
	var resp Response
	if len(msg.Header.Values(payloadbox.Header)) != 0 || json.Unmarshal(msg.Data, &resp) != nil ||
		len(resp.Keys) != 0 || resp.Error != errorUnavailable {
		t.Fatalf("reply %v %s, want a plaintext errorUnavailable with no keys", msg.Header, msg.Data)
	}
}

// fakeFarmer answers web-01's requests with whatever reply builds from
// the request's id.
func fakeFarmer(t *testing.T, nc *nats.Conn, reply func(reqID string) *nats.Msg) {
	t.Helper()
	sub, err := nc.Subscribe(SproutSubject("web-01"), func(m *nats.Msg) {
		var req Request
		_ = json.Unmarshal(m.Data, &req)
		_ = m.RespondMsg(reply(req.ID))
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sub.Unsubscribe() })
}

func sealedMsg(data []byte) *nats.Msg {
	m := nats.NewMsg("")
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Data = data
	return m
}

func TestFetch_BoxReadySproutRejectsBadReplies(t *testing.T) {
	good := func(t *testing.T) Response {
		ks := twoVersions(t)
		return Response{Keys: []KeyVersion{{Version: 1, PublicKey: ks[0].Key}, {Version: 2, PublicKey: ks[1].Key}}}
	}
	for name, tc := range map[string]struct {
		reply   func(t *testing.T, reqID string) *nats.Msg
		wantErr error
	}{
		// Control: the same fake farmer, sealing correctly, is accepted,
		// so the cases below fail for the reason they name.
		"control": {
			reply: func(t *testing.T, reqID string) *nats.Msg {
				data, _, err := pki.SealToSprout("t_1", "web-01", payloadbox.PurposeFleetSigningResponse, reqID, good(t))
				if err != nil {
					t.Error(err)
				}
				return sealedMsg(data)
			},
			wantErr: nil,
		},
		// A rogue imas.> Subscriber answering with its own keys: the
		// downgrade this change closes.
		"plaintext": {
			reply: func(t *testing.T, _ string) *nats.Msg {
				b, _ := json.Marshal(good(t))
				return &nats.Msg{Data: b}
			},
			wantErr: ErrReplyNotSealed,
		},
		"plaintext error": {
			reply: func(t *testing.T, _ string) *nats.Msg {
				return &nats.Msg{Data: []byte(`{"error":"unavailable"}`)}
			},
			wantErr: ErrReplyNotSealed,
		},
		"wrong purpose": {
			reply: func(t *testing.T, reqID string) *nats.Msg {
				data, _, err := pki.SealToSprout("t_1", "web-01", payloadbox.PurposeCmdRunRequest, reqID, good(t))
				if err != nil {
					t.Error(err)
				}
				return sealedMsg(data)
			},
			wantErr: payloadbox.ErrOpen,
		},
		"stale ReplyTo": {
			reply: func(t *testing.T, _ string) *nats.Msg {
				other, _ := payloadbox.NewID()
				data, _, err := pki.SealToSprout("t_1", "web-01", payloadbox.PurposeFleetSigningResponse, other, good(t))
				if err != nil {
					t.Error(err)
				}
				return sealedMsg(data)
			},
			wantErr: payloadbox.ErrOpen,
		},
		"no ReplyTo": {
			reply: func(t *testing.T, _ string) *nats.Msg {
				data, _, err := pki.SealToSprout("t_1", "web-01", payloadbox.PurposeFleetSigningResponse, "", good(t))
				if err != nil {
					t.Error(err)
				}
				return sealedMsg(data)
			},
			wantErr: payloadbox.ErrOpen,
		},
		"sealed for another sprout": {
			reply: func(t *testing.T, reqID string) *nats.Msg {
				data, _, err := pki.SealToSprout("t_1", "web-02", payloadbox.PurposeFleetSigningResponse, reqID, good(t))
				if err != nil {
					t.Error(err)
				}
				return sealedMsg(data)
			},
			wantErr: payloadbox.ErrOpen,
		},
		"marked sealed, isn't": {
			reply: func(t *testing.T, _ string) *nats.Msg {
				b, _ := json.Marshal(good(t))
				return sealedMsg(b)
			},
			wantErr: payloadbox.ErrOpen,
		},
		"unknown payload format": {
			reply: func(t *testing.T, _ string) *nats.Msg {
				b, _ := json.Marshal(good(t))
				m := nats.NewMsg("")
				m.Header.Set(payloadbox.Header, "box2")
				m.Data = b
				return m
			},
			wantErr: payloadbox.ErrOpen,
		},
	} {
		t.Run(name, func(t *testing.T) {
			nc := startBus(t)
			readySprout(t, "t_1", "web-01")
			if name == "sealed for another sprout" {
				// web-02 is a real sprout of the tenant, with its own box key.
				pub, _, _ := ed25519.GenerateKey(rand.Reader) // any 32 bytes
				if err := pki.RotateSproutBoxKey("t_1", "web-02", base64.StdEncoding.EncodeToString(pub), time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			fakeFarmer(t, nc, func(reqID string) *nats.Msg { return tc.reply(t, reqID) })
			ks, err := Fetch(t.Context(), nc, "web-01")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Fetch = %v, %v; want %v", ks, err, tc.wantErr)
			}
		})
	}
}

// A genuine sealed reply captured off the bus can't answer a later
// request: its ReplyTo names the request it was sealed for.
func TestFetch_ReplayedSealedReplyIsRejected(t *testing.T) {
	nc := startBus(t)
	readySprout(t, "t_1", "web-01")
	useKeys(t, twoVersions(t))
	farmer, err := nats.Connect(nc.ConnectedUrl())
	if err != nil {
		t.Fatal(err)
	}
	defer farmer.Close()
	if err := RegisterFarmerListener("t_1", farmer); err != nil {
		t.Fatal(err)
	}
	farmer.Flush()
	id, _ := payloadbox.NewID()
	captured := rawRequest(t, nc, "web-01", requestBody(t, id))
	if captured.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		t.Fatalf("farmer didn't seal: %v", captured.Header)
	}

	// Farmer goes quiet; the bus replays the captured reply instead,
	// under the same keys.
	farmer.Close()
	fakeFarmer(t, nc, func(string) *nats.Msg { return sealedMsg(captured.Data) })
	if _, err := Fetch(t.Context(), nc, "web-01"); !errors.Is(err, payloadbox.ErrOpen) {
		t.Fatalf("Fetch accepted a replayed reply: %v", err)
	}
}
