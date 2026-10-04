// Package clienttest is a stand-in farmer for tests of the imas CLI's
// client side (internal/api/client and its callers): it answers the CLI's
// sealed imas.api.* requests with sealed replies, so those tests exercise
// the real sealing path (pki.CLISealRequest, pki.CLIOpenReply) without a
// farmer, a database or OpenBao. It holds the tenant box keypair a real
// farmer keeps in OpenBao, and configures the CLI (jety) to pin it.
//
// Test code only: nothing outside _test.go files imports it.
package clienttest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/taigrr/jety"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// TenantID is the tenant the fake farmer and the CLI it configures use.
const TenantID = "t_clienttest"

// Farmer is the fake farmer's keys and the CLI user it serves.
type Farmer struct {
	TenantID string
	// UserID is the CLI user's NKey public key, Seed its seed.
	UserID string
	Seed   []byte
	// KeyFile is the CLI box private key file.
	KeyFile string

	tenantPub, tenantPriv *[32]byte
	cliPub                *[32]byte
}

// Setup creates a CLI user (NKey and CLI box key) and a tenant box
// keypair, and configures the CLI through jety to use them: privkey,
// cliboxprivfile, tenantboxpub and tenantid. Cleanup clears those keys.
func Setup(t testing.TB) *Farmer {
	t.Helper()
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := kp.Seed()
	userID, _ := kp.PublicKey()
	tenantPub, tenantPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &Farmer{
		TenantID: TenantID, UserID: userID, Seed: seed,
		KeyFile:   filepath.Join(t.TempDir(), "cli-box.key"),
		tenantPub: tenantPub, tenantPriv: tenantPriv,
	}
	prev := map[string]any{}
	for _, k := range []string{"privkey", pki.CLIBoxPrivFileKey, pki.CLITenantBoxPubKey, pki.CLITenantIDKey} {
		prev[k] = jety.Get(k)
	}
	t.Cleanup(func() {
		for k, v := range prev {
			jety.Set(k, v)
		}
	})
	jety.Set("privkey", string(seed))
	jety.Set(pki.CLIBoxPrivFileKey, f.KeyFile)
	jety.Set(pki.CLITenantBoxPubKey, base64.StdEncoding.EncodeToString(tenantPub[:]))
	jety.Set(pki.CLITenantIDKey, f.TenantID)
	pub, err := pki.GenerateCLIBoxKey(f.KeyFile, false)
	if err != nil {
		t.Fatal(err)
	}
	f.cliPub, err = decode32(pub)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func decode32(b64 string) (*[32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("clienttest: not a 32-byte key")
	}
	var k [32]byte
	copy(k[:], raw)
	return &k, nil
}

// TenantPub is the tenant box public key the CLI pins, standard base64.
func (f *Farmer) TenantPub() string { return base64.StdEncoding.EncodeToString(f.tenantPub[:]) }

// CLIBoxPub is the CLI user's box public key, standard base64.
func (f *Farmer) CLIBoxPub() string { return base64.StdEncoding.EncodeToString(f.cliPub[:]) }

// Request is a sealed CLI request the fake farmer opened.
type Request struct {
	Method, Subject, ID string
	Params              json.RawMessage
}

// Open opens m, a sealed CLI request, as farmer would: the payloadbox
// marker and principal header, then the box under the CLI user's key,
// bound to the method and subject m arrived on.
func (f *Farmer) Open(m *nats.Msg) (*Request, error) {
	if m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		return nil, errors.New("clienttest: plaintext request")
	}
	if m.Header.Get(payloadbox.PrincipalHeader) != f.UserID {
		return nil, errors.New("clienttest: wrong principal header")
	}
	method, ok := strings.CutPrefix(m.Subject, pki.CLIAPISubjectPrefix)
	if !ok {
		return nil, errors.New("clienttest: not an API subject")
	}
	purpose := payloadbox.PurposeCLIRequest
	if method == pki.MethodAuthRotateKey {
		purpose = payloadbox.PurposeCLIUserKeySubmit
	}
	msg, body, err := payloadbox.OpenCall(m.Data, f.pairs(), payloadbox.CallExpect{
		Purpose: purpose, TenantID: f.TenantID, Principal: f.UserID, Method: method, Subject: m.Subject,
	})
	if err != nil {
		return nil, err
	}
	return &Request{Method: method, Subject: m.Subject, ID: msg.ID, Params: body.Params}, nil
}

func (f *Farmer) pairs() []payloadbox.KeyPair {
	return []payloadbox.KeyPair{{PeerPub: f.cliPub, Priv: f.tenantPriv}}
}

// SealReply seals farmer's reply to req: result, or errText if not empty.
func (f *Farmer) SealReply(req *Request, result any, errText string) ([]byte, error) {
	r := payloadbox.Reply{
		Purpose: payloadbox.PurposeCLIReply, TenantID: f.TenantID, Principal: f.UserID,
		ReplyTo: req.ID, Method: req.Method, Subject: req.Subject, Result: result, Error: errText,
	}
	if errText != "" {
		r.Result = nil
	}
	return payloadbox.SealReply(r, f.pairs())
}

// Reply answers m, the request req was opened from, with a sealed reply.
func (f *Farmer) Reply(m *nats.Msg, req *Request, result any, errText string) error {
	data, err := f.SealReply(req, result, errText)
	if err != nil {
		return err
	}
	resp := nats.NewMsg(m.Reply)
	resp.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	resp.Data = data
	return m.RespondMsg(resp)
}

// Refuse answers m with a fixed refusal code and no body, as farmer does
// for a request that doesn't open.
func Refuse(m *nats.Msg, code string) error {
	resp := nats.NewMsg(m.Reply)
	resp.Header.Set(payloadbox.ErrorHeader, code)
	return m.RespondMsg(resp)
}

// Handle subscribes to imas.api.<method> on nc and answers every request
// that opens with fn's result, sealed; fn's error travels inside the
// sealed reply, as farmer's handler errors do. A request that doesn't
// open is refused (open-failed) and fails the test.
func (f *Farmer) Handle(t testing.TB, nc *nats.Conn, method string, fn func(params json.RawMessage) (any, error)) *nats.Subscription {
	t.Helper()
	sub, err := nc.Subscribe(pki.CLIAPISubjectPrefix+method, func(m *nats.Msg) {
		req, err := f.Open(m)
		if err != nil {
			t.Errorf("clienttest: %s didn't open: %v", m.Subject, err)
			_ = Refuse(m, payloadbox.ErrorCodeOpenFailed)
			return
		}
		result, herr := fn(req.Params)
		errText := ""
		if herr != nil {
			errText = herr.Error()
		}
		if err := f.Reply(m, req, result, errText); err != nil {
			t.Errorf("clienttest: replying to %s: %v", m.Subject, err)
		}
	})
	if err != nil {
		t.Fatalf("clienttest: subscribe %s: %v", method, err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return sub
}

// Result is shorthand for a Handle fn that always answers result.
func Result(result any) func(json.RawMessage) (any, error) {
	return func(json.RawMessage) (any, error) { return result, nil }
}

// Error is shorthand for a Handle fn that always answers with errText.
func Error(errText string) func(json.RawMessage) (any, error) {
	return func(json.RawMessage) (any, error) { return nil, errors.New(errText) }
}

// Impostor returns a farmer that knows this CLI's public keys but holds a
// tenant key the CLI doesn't pin: what a compromised bus sealing its own
// replies is.
func (f *Farmer) Impostor(t testing.TB) *Farmer {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g := *f
	g.tenantPub, g.tenantPriv = pub, priv
	return &g
}

// RemoveKeyFile deletes the CLI box key file (a CLI with no key).
func (f *Farmer) RemoveKeyFile(t testing.TB) {
	t.Helper()
	if err := os.Remove(f.KeyFile); err != nil {
		t.Fatal(err)
	}
}
