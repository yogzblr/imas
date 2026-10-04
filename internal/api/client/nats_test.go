package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/api/client/clienttest"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// testFarmer is the sealed stand-in farmer the current test's mocks
// answer as (startTestNATS sets it).
var testFarmer *clienttest.Farmer

// startTestNATS starts an embedded NATS server, connects NatsConn to it,
// and configures this CLI's keys against a sealed stand-in farmer
// (testFarmer). Returns a cleanup function that must be deferred.
func startTestNATS(t *testing.T) func() {
	t.Helper()

	opts := &server.Options{
		Host: "127.0.0.1",
		Port: -1, // random port
	}
	ns, err := server.NewServer(opts)
	if err != nil {
		t.Fatalf("start test NATS server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server failed to become ready")
	}

	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		ns.Shutdown()
		t.Fatalf("connect to test NATS: %v", err)
	}

	testFarmer = clienttest.Setup(t)
	NatsConn = nc
	return func() {
		NatsConn = nil
		nc.Close()
		ns.Shutdown()
	}
}

// method is subject without the imas.api. prefix.
func method(subject string) string { return strings.TrimPrefix(subject, "imas.api.") }

// mockHandler answers subject's sealed requests with response, sealed.
func mockHandler(t *testing.T, nc *nats.Conn, subject string, response interface{}) *nats.Subscription {
	t.Helper()
	return testFarmer.Handle(t, nc, method(subject), clienttest.Result(response))
}

// mockErrorHandler answers subject's sealed requests with a handler
// error, inside the sealed reply.
func mockErrorHandler(t *testing.T, nc *nats.Conn, subject, errMsg string) *nats.Subscription {
	t.Helper()
	return testFarmer.Handle(t, nc, method(subject), clienttest.Error(errMsg))
}

// mockBadJSONHandler answers with a result that is not valid JSON for the
// expected type (forces an unmarshal error in callers).
func mockBadJSONHandler(t *testing.T, nc *nats.Conn, subject string) *nats.Subscription {
	t.Helper()
	return testFarmer.Handle(t, nc, method(subject), clienttest.Result(json.RawMessage(`"not an object"`)))
}

// --- NatsRequest tests ---

func TestNatsRequest_NilConn(t *testing.T) {
	old := NatsConn
	NatsConn = nil
	defer func() { NatsConn = old }()

	_, err := NatsRequest("version", nil)
	if err == nil {
		t.Fatal("expected error for nil NatsConn")
	}
	if err.Error() != "NATS connection not established" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNatsRequest_Success(t *testing.T) {
	cleanup := startTestNATS(t)
	defer cleanup()

	want := map[string]string{"tag": "v2.0.0"}
	mockHandler(t, NatsConn, "imas.api.version", want)

	result, err := NatsRequest("version", nil)
	if err != nil {
		t.Fatalf("NatsRequest: %v", err)
	}

	var got map[string]string
	if err := json.Unmarshal(result, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if got["tag"] != "v2.0.0" {
		t.Fatalf("expected tag v2.0.0, got %q", got["tag"])
	}
}

func TestNatsRequest_ErrorResponse(t *testing.T) {
	cleanup := startTestNATS(t)
	defer cleanup()

	mockErrorHandler(t, NatsConn, "imas.api.fail", "something went wrong")

	_, err := NatsRequest("fail", nil)
	if err == nil {
		t.Fatal("expected error from error response")
	}
	if err.Error() != "something went wrong" {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The request on the wire is sealed: no params, no method name in the
// body readable by the bus, and no token anywhere. The farmer side opens
// it and gets the params back exactly, []byte params included.
func TestNatsRequest_WithParams(t *testing.T) {
	cleanup := startTestNATS(t)
	defer cleanup()

	wires := make(chan []byte, 4)
	tap, err := NatsConn.Subscribe("imas.api.echo", func(m *nats.Msg) { wires <- append([]byte(nil), m.Data...) })
	if err != nil {
		t.Fatal(err)
	}
	defer tap.Unsubscribe()
	testFarmer.Handle(t, NatsConn, "echo", func(p json.RawMessage) (any, error) { return p, nil })

	for _, params := range []any{map[string]string{"name": "web-servers"}, []byte(`{"name":"web-servers"}`)} {
		result, err := NatsRequest("echo", params)
		if err != nil {
			t.Fatalf("NatsRequest: %v", err)
		}
		var got map[string]string
		if err := json.Unmarshal(result, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got["name"] != "web-servers" {
			t.Fatalf("expected name web-servers, got %q", got["name"])
		}
		wire := <-wires
		if len(wire) == 0 || bytes.Contains(wire, []byte("web-servers")) || bytes.Contains(wire, []byte("token")) {
			t.Fatalf("request readable on the wire: %s", wire)
		}
	}
}

func TestNatsRequest_Timeout(t *testing.T) {
	cleanup := startTestNATS(t)
	defer cleanup()

	// Set a short timeout and don't register any handler
	old := NatsRequestTimeout
	NatsRequestTimeout = 50 * time.Millisecond
	defer func() { NatsRequestTimeout = old }()

	_, err := NatsRequest("nonexistent.method", nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

// respondWith subscribes to imas.api.<m> and answers each request with
// whatever answer builds from it.
func respondWith(t *testing.T, m string, answer func(*nats.Msg) *nats.Msg) {
	t.Helper()
	sub, err := NatsConn.Subscribe("imas.api."+m, func(msg *nats.Msg) {
		resp := answer(msg)
		resp.Subject = msg.Reply
		if err := msg.RespondMsg(resp); err != nil {
			t.Errorf("respond: %v", err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sub.Unsubscribe() })
	NatsConn.Flush()
}

// A plaintext reply is an error, never a result: anything on the bus
// could have written it.
func TestNatsRequest_PlaintextReplyRefused(t *testing.T) {
	cleanup := startTestNATS(t)
	defer cleanup()

	respondWith(t, "jobs.list", func(*nats.Msg) *nats.Msg {
		return &nats.Msg{Data: []byte(`{"result":[{"jid":"forged"}]}`)}
	})
	if _, err := NatsRequest("jobs.list", nil); !errors.Is(err, ErrPlaintextReply) {
		t.Fatalf("plaintext reply: %v, want ErrPlaintextReply", err)
	}
	// Not even with the payloadbox marker on a body that isn't sealed.
	respondWith(t, "jobs.get", func(*nats.Msg) *nats.Msg {
		m := nats.NewMsg("")
		m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
		m.Data = []byte(`{"result":{"jid":"forged"}}`)
		return m
	})
	if _, err := NatsRequest("jobs.get", nil); !errors.Is(err, ErrReplyDidNotOpen) {
		t.Fatalf("marked plaintext reply: %v, want ErrReplyDidNotOpen", err)
	}
}

// A genuine sealed reply to another request, another method's reply, or
// one sealed by a key that isn't the pinned tenant key, is refused.
func TestNatsRequest_ReplyMustAnswerThisRequest(t *testing.T) {
	cleanup := startTestNATS(t)
	defer cleanup()

	// A reply farmer sealed to an earlier request of the same method:
	// what a bus replaying a captured reply sends.
	var earlier []byte
	respondWith(t, "jobs.list", func(m *nats.Msg) *nats.Msg {
		req, err := testFarmer.Open(m)
		if err != nil {
			t.Fatal(err)
		}
		data, err := testFarmer.SealReply(req, []string{"genuine"}, "")
		if err != nil {
			t.Fatal(err)
		}
		if earlier == nil {
			earlier = data
		} else {
			data = earlier
		}
		resp := nats.NewMsg("")
		resp.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
		resp.Data = data
		return resp
	})
	if _, err := NatsRequest("jobs.list", nil); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if _, err := NatsRequest("jobs.list", nil); !errors.Is(err, ErrReplyDidNotOpen) {
		t.Fatalf("replayed reply: %v, want ErrReplyDidNotOpen", err)
	}

	// The reply to a jobs.list moved onto a jobs.delete.
	respondWith(t, "jobs.delete", func(m *nats.Msg) *nats.Msg {
		req, err := testFarmer.Open(m)
		if err != nil {
			t.Fatal(err)
		}
		req.Method, req.Subject = "jobs.list", "imas.api.jobs.list"
		data, _ := testFarmer.SealReply(req, []string{"ok"}, "")
		resp := nats.NewMsg("")
		resp.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
		resp.Data = data
		return resp
	})
	if _, err := NatsRequest("jobs.delete", map[string]string{"jid": "j"}); !errors.Is(err, ErrReplyDidNotOpen) {
		t.Fatalf("moved reply: %v, want ErrReplyDidNotOpen", err)
	}

	// A bus answering with its own key: it knows the CLI's public keys,
	// not the tenant key the CLI pins.
	impostor := testFarmer.Impostor(t)
	respondWith(t, "jobs.forsprout", func(m *nats.Msg) *nats.Msg {
		req := &clienttest.Request{Method: "jobs.forsprout", Subject: m.Subject}
		if opened, err := testFarmer.Open(m); err == nil {
			req.ID = opened.ID // the bus can't open it; give it the ID anyway
		}
		data, err := impostor.SealReply(req, []string{"forged"}, "")
		if err != nil {
			t.Fatal(err)
		}
		resp := nats.NewMsg("")
		resp.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
		resp.Data = data
		return resp
	})
	if _, err := NatsRequest("jobs.forsprout", map[string]string{"sprout_id": "web-1"}); !errors.Is(err, ErrReplyDidNotOpen) {
		t.Fatalf("reply under another tenant key: %v, want ErrReplyDidNotOpen", err)
	}
}

// A refusal before any handler ran comes back as a fixed code.
func TestNatsRequest_Refusal(t *testing.T) {
	cleanup := startTestNATS(t)
	defer cleanup()

	respondWith(t, "jobs.list", func(*nats.Msg) *nats.Msg {
		m := nats.NewMsg("")
		m.Header.Set(payloadbox.ErrorHeader, payloadbox.ErrorCodeOpenFailed)
		return m
	})
	_, err := NatsRequest("jobs.list", nil)
	var refused *RefusedError
	if !errors.As(err, &refused) || refused.Code != payloadbox.ErrorCodeOpenFailed {
		t.Fatalf("refusal: %v, want a RefusedError with open-failed", err)
	}
}

// Without a CLI box key, or without a pinned tenant, nothing is sent.
func TestNatsRequest_NotConfigured(t *testing.T) {
	cleanup := startTestNATS(t)
	defer cleanup()

	testFarmer.RemoveKeyFile(t)
	if _, err := NatsRequest("jobs.list", nil); !errors.Is(err, pki.ErrCLIBoxNotConfigured) {
		t.Fatalf("no CLI box key: %v, want ErrCLIBoxNotConfigured", err)
	}
}

// The CLI verifies the bus cert against config.BusTLSServerName(), not
// config.FarmerInterface: with farmerbusurl pointing at a separate bus
// Service, farmerinterface is not a name the bus cert carries.
func TestBusTLSConfig_ServerName(t *testing.T) {
	origIface, origURL, origName := config.FarmerInterface, config.FarmerBusURL, config.FarmerBusTLSServerName
	t.Cleanup(func() {
		config.FarmerInterface, config.FarmerBusURL, config.FarmerBusTLSServerName = origIface, origURL, origName
	})

	tests := []struct {
		name, iface, busURL, serverName, want string
	}{
		{"default farmerinterface:port", "farmer.example.com", "farmer.example.com:5406", "", "farmer.example.com"},
		{"wildcard single host", "0.0.0.0", "0.0.0.0:5406", "", "localhost"},
		{"farmerbusurl elsewhere", "farmer.example.com", "tls://imas-nats-bus.imas.svc.cluster.local:5406", "", "imas-nats-bus.imas.svc.cluster.local"},
		{"explicit server name", "farmer.example.com", "tls://10.0.0.5:5406", "bus.example.test", "bus.example.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.FarmerInterface = tt.iface
			config.FarmerBusURL = tt.busURL
			config.FarmerBusTLSServerName = tt.serverName
			pool := x509.NewCertPool()

			cfg := busTLSConfig(pool)

			if cfg.ServerName != tt.want {
				t.Errorf("ServerName = %q, want %q", cfg.ServerName, tt.want)
			}
			if cfg.RootCAs != pool {
				t.Error("RootCAs is not the pool passed in")
			}
			if cfg.MinVersion != tls.VersionTLS12 {
				t.Errorf("MinVersion = %#x, want TLS 1.2", cfg.MinVersion)
			}
		})
	}
}
