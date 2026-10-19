package fakestack

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/facts"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// The bus behind the fake Envoy: an in-process NATS server whose websocket
// listener the fake proxies "/" to when the handshake carries a gateway
// JWT the fake minted (Envoy's jwt_authn). It takes any client (no auth:
// the fake proves the harness's plumbing, not the bus's), and the fake's
// own subscriber plays farmer's facts and step event listeners
// (internal/facts, internal/jobs): a sealed facts report that opens under
// the sprout's box key and the tenant's key becomes the sprout's props and
// clears its "needs upgrade" marker; a plaintext facts report or step
// event is refused and sets the marker; anything else is refused.
type fakeBus struct {
	ns    *server.Server
	nc    *nats.Conn
	proxy *httputil.ReverseProxy
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func startBus(s *Stack) (*fakeBus, error) {
	wsPort, err := freePort()
	if err != nil {
		return nil, err
	}
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: server.RANDOM_PORT, NoLog: true, NoSigs: true,
		Websocket: server.WebsocketOpts{Host: "127.0.0.1", Port: wsPort, NoTLS: true}})
	if err != nil {
		return nil, err
	}
	go ns.Start()
	if !ns.ReadyForConnections(10 * time.Second) {
		ns.Shutdown()
		return nil, fmt.Errorf("the NATS server did not start")
	}
	nc, err := nats.Connect(ns.ClientURL(), nats.Name("fakestack-farmer"))
	if err != nil {
		ns.Shutdown()
		return nil, err
	}
	b := &fakeBus{ns: ns, nc: nc}
	for subject, handle := range map[string]func(*nats.Msg){
		"imas.sprouts.*.facts": s.onFacts,
		"imas.cook.*.*":        s.onStepEvent,
	} {
		if _, err := nc.Subscribe(subject, handle); err != nil {
			b.close()
			return nil, err
		}
	}
	if err := nc.Flush(); err != nil {
		b.close()
		return nil, err
	}
	target, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", wsPort))
	b.proxy = httputil.NewSingleHostReverseProxy(target)
	return b, nil
}

func (b *fakeBus) close() {
	if b == nil {
		return
	}
	if b.nc != nil {
		b.nc.Close()
	}
	b.ns.Shutdown()
}

// gatewayOK reports whether the websocket handshake carries a gateway JWT
// the fake minted and that hasn't expired.
func (s *Stack) gatewayOK(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || !s.hmacOK(parts[0]+"."+parts[1], parts[2]) {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var c struct {
		Iss string `json:"iss"`
		Exp int64  `json:"exp"`
	}
	return json.Unmarshal(b, &c) == nil && c.Iss == "imas-gateway" && time.Now().Unix() < c.Exp
}

// tenantsOfSprout lists the tenants holding sproutID; s.mu is held.
func (s *Stack) tenantsOfSprout(sproutID string) []string {
	var out []string
	for key := range s.sprouts {
		if t, sid, ok := strings.Cut(key, "/"); ok && sid == sproutID {
			out = append(out, t)
		}
	}
	return out
}

func subjectSprout(subject string, at int) string {
	parts := strings.Split(subject, ".")
	if at < len(parts) {
		return parts[at]
	}
	return ""
}

// onFacts is farmer's facts listener.
func (s *Stack) onFacts(m *nats.Msg) {
	sid := subjectSprout(m.Subject, 2)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tid := range s.tenantsOfSprout(sid) {
		if m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
			s.markers[tid+"/"+sid] = "facts"
			continue
		}
		sp := s.sprouts[tid+"/"+sid]
		pub, err := base64.StdEncoding.DecodeString(sp.boxPub)
		if err != nil || len(pub) != 32 || s.tenantBox[tid] == nil {
			continue
		}
		var peer [32]byte
		copy(peer[:], pub)
		msg, err := payloadbox.Open(m.Data, []payloadbox.KeyPair{{PeerPub: &peer, Priv: s.tenantBox[tid]}},
			payloadbox.Expect{Purpose: payloadbox.PurposeFacts, TenantID: tid, SproutID: sid})
		if err != nil {
			continue
		}
		var sf facts.SystemFacts
		if json.Unmarshal(msg.Body, &sf) != nil || sf.SproutID != sid {
			continue
		}
		delete(s.markers, tid+"/"+sid)
		exp := time.Now().Add(5 * time.Minute)
		s.setProps(tid, sid, map[string]string{"os": sf.OS, "arch": sf.Arch, "hostname": sf.Hostname,
			"go_version": sf.GoVersion, "num_cpu": fmt.Sprint(sf.NumCPU)}, exp)
	}
}

// onStepEvent is farmer's job store listener: a plaintext event is
// refused and marks the sprout; the fake records no sealed one (its
// cooks record their jobs themselves).
func (s *Stack) onStepEvent(m *nats.Msg) {
	if m.Header.Get(payloadbox.Header) == payloadbox.HeaderBox1 {
		return
	}
	sid := subjectSprout(m.Subject, 2)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tid := range s.tenantsOfSprout(sid) {
		s.markers[tid+"/"+sid] = "cook step"
	}
}
