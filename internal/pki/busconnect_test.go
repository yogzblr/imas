package pki

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/envoytest"
)

func TestValidateBusURLs(t *testing.T) {
	ok := [][]string{
		nil,
		{"wss://edge:8443"},
		{" wss://edge1:8443 ", "wss://edge2.example.com:443/nats"},
		{"tls://bus:4222", "nats://bus2:4222"},
		{"WSS://edge:8443"},
		{"wss://[::1]:8443"},
	}
	for _, urls := range ok {
		if _, err := ValidateBusURLs(urls); err != nil {
			t.Errorf("ValidateBusURLs(%q): %v", urls, err)
		}
	}
	got, _ := ValidateBusURLs([]string{" wss://edge:8443 "})
	if !reflect.DeepEqual(got, []string{"wss://edge:8443"}) {
		t.Errorf("not trimmed: %q", got)
	}

	bad := map[string][]string{
		"plaintext websocket": {"ws://edge:8443"},
		"https":               {"https://edge:8443"},
		"no scheme":           {"edge:8443"},
		"no host":             {"wss://:8443"},
		"empty":               {""},
		"credentials":         {"wss://user:pass@edge:8443"},
		"token":               {"tls://sometoken@bus:4222"},
		"query":               {"wss://edge:8443/?x=1"},
		"fragment":            {"wss://edge:8443#x"},
		"path on tls":         {"tls://bus:4222/foo"},
		"mixed":               {"wss://edge:8443", "tls://bus:4222"},
		"too long":            {"wss://" + strings.Repeat("a", maxBusURLLength) + ":1"},
	}
	for name, urls := range bad {
		if _, err := ValidateBusURLs(urls); err == nil {
			t.Errorf("%s: ValidateBusURLs(%q) accepted", name, urls)
		}
	}
	many := make([]string, maxBusURLs+1)
	for i := range many {
		many[i] = "wss://edge:" + strconv.Itoa(8000+i)
	}
	if _, err := ValidateBusURLs(many); err == nil {
		t.Error("accepted more than maxBusURLs")
	}
	if _, err := ValidateBusURLs([]string{"wss://u:secretpw@edge:1"}); err == nil || strings.Contains(err.Error(), "secretpw") {
		t.Errorf("credentials error should not echo the password: %v", err)
	}
}

func TestResolveSproutBusURLs_Precedence(t *testing.T) {
	setupSproutFiles(t)
	oldBus := config.FarmerBusURL
	t.Cleanup(func() { config.FarmerBusURL = oldBus })
	config.FarmerBusURL = "farmer:5406"

	urls, src, err := ResolveSproutBusURLs()
	if err != nil || src != BusURLsFromLegacy || !reflect.DeepEqual(urls, []string{"farmer:5406"}) {
		t.Fatalf("nothing enrolled or pinned: got %q %q %v, want the legacy FarmerBusURL", urls, src, err)
	}

	if err := persistBusURLs([]string{"wss://edge1:8443", "wss://edge2:8443"}); err != nil {
		t.Fatal(err)
	}
	urls, src, err = ResolveSproutBusURLs()
	if err != nil || src != BusURLsFromEnrollment || !reflect.DeepEqual(urls, []string{"wss://edge1:8443", "wss://edge2:8443"}) {
		t.Fatalf("enrolled: got %q %q %v", urls, src, err)
	}

	config.BusURLs = []string{"wss://pinned:443"}
	urls, src, err = ResolveSproutBusURLs()
	if err != nil || src != BusURLsFromConfig || !reflect.DeepEqual(urls, []string{"wss://pinned:443"}) {
		t.Fatalf("pinned: got %q %q %v", urls, src, err)
	}

	// A bad pin is an error, not a fallback to the enrolled list.
	config.BusURLs = []string{"ws://pinned:80"}
	if _, _, err := ResolveSproutBusURLs(); err == nil {
		t.Fatal("invalid busurls pin accepted")
	}
	config.BusURLs = nil

	// Neither is a corrupt or tampered persisted list.
	for _, content := range []string{"not json", `["ws://edge:80"]`, `["wss://u:p@edge:1"]`} {
		if err := os.WriteFile(config.SproutBusURLsFile, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ResolveSproutBusURLs(); err == nil {
			t.Errorf("persisted %s accepted", content)
		}
	}

	// Enrolling without nats_urls removes the stale list.
	if err := persistBusURLs(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(config.SproutBusURLsFile); !os.IsNotExist(err) {
		t.Fatalf("bus URLs file not removed: %v", err)
	}
	if _, src, _ := ResolveSproutBusURLs(); src != BusURLsFromLegacy {
		t.Errorf("after removal: source %q, want legacy", src)
	}

	config.FarmerBusURL = ""
	if _, _, err := ResolveSproutBusURLs(); err == nil {
		t.Error("no URL anywhere should be an error")
	}
}

// appliedOptions runs b's options over nats.go's defaults.
func appliedOptions(t *testing.T, b *SproutBus) nats.Options {
	t.Helper()
	o := nats.GetDefaultOptions()
	for _, opt := range b.Options {
		if err := opt(&o); err != nil {
			t.Fatal(err)
		}
	}
	return o
}

func TestLoadSproutBus_Options(t *testing.T) {
	setupTestPKI(t)
	setupSproutFiles(t)
	config.SproutRootCA = config.RootCA
	oldBus := config.FarmerBusURL
	t.Cleanup(func() { config.FarmerBusURL = oldBus })
	config.FarmerBusURL = "farmer:5406"

	if _, err := LoadSproutBus(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("unenrolled: err = %v, want ErrNotEnrolled", err)
	}
	if err := os.WriteFile(config.SproutUserJWTFile, []byte("user.jwt"), 0o600); err != nil {
		t.Fatal(err)
	}

	b, err := LoadSproutBus()
	if err != nil {
		t.Fatal(err)
	}
	o := appliedOptions(t, b)
	if !o.Secure || o.TLSConfig == nil || o.TLSConfig.RootCAs == nil {
		t.Fatal("bus options are not TLS pinned to SproutRootCA")
	}
	if o.TLSConfig.ServerName != "" {
		t.Errorf("ServerName = %q; want empty, so each URL's host is verified", o.TLSConfig.ServerName)
	}
	if o.UserJWT == nil || o.SignatureCB == nil || o.WebSocketConnectionHeadersHandler == nil {
		t.Error("missing User JWT, NKey signature or gateway JWT header option")
	}
	if o.IgnoreDiscoveredServers {
		t.Error("legacy FarmerBusURL should keep using discovered servers")
	}
	if o.CustomDialer != nil || o.SkipHostLookup || b.Proxy != "" {
		t.Error("no busproxyurl, yet the bus options dial through a proxy")
	}

	if err := persistBusURLs([]string{"wss://edge:8443"}); err != nil {
		t.Fatal(err)
	}
	b, err = LoadSproutBus()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(b.Servers, []string{"wss://edge:8443"}) || b.Source != BusURLsFromEnrollment {
		t.Errorf("servers %q from %q", b.Servers, b.Source)
	}
	if !appliedOptions(t, b).IgnoreDiscoveredServers {
		t.Error("enrolled URLs should ignore servers the bus advertises")
	}

	if err := os.WriteFile(config.SproutRootCA, []byte("not a cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSproutBus(); err == nil {
		t.Error("unparseable root CA accepted")
	}
}

func TestEnrollSprout_RejectsBadNatsURLs(t *testing.T) {
	store, _ := setupEnrollTest(t)
	newJWSGatewayMinter(t)
	config.GatewayJWTTTL = time.Hour
	store.rows["ek_1"] = &enrollmentKeyRow{
		TenantID: "t_1", KeyHash: hashSecret("supersecret"),
		Expiry: time.Now().Add(time.Hour), MaxUses: 5,
	}
	setupSproutFiles(t)
	srv := startEnrollServer(t)
	srv.setNatsURLs("ws://edge:80")
	boxPub, err := EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EnrollSprout(t.Context(), "ek_1.supersecret", "web-01", boxPub); err == nil || !strings.Contains(err.Error(), "nats_urls") {
		t.Fatalf("EnrollSprout with ws:// nats_urls: err = %v", err)
	}
	if SproutEnrolled() {
		t.Fatal("rejected response left the sprout enrolled")
	}
}

// Enrollment's nats_urls reach the bus: persisted, then dialled by
// LoadSproutBus over wss:// (straight to nats-server's websocket
// listener here; envoy_e2e_test.go does the same through Envoy). Also
// covers the legacy FarmerBusURL fallback against the same bus.
func TestSproutBus_ConnectsToEnrolledURLs(t *testing.T) {
	store, _ := setupEnrollTest(t)
	useRealFarmerKey(t)
	newJWSGatewayMinter(t)
	config.GatewayJWTTTL = time.Hour
	origWS := config.FarmerWSPort
	wsPort := envoytest.FreePort(t)
	config.FarmerWSPort = strconv.Itoa(wsPort)
	t.Cleanup(func() { config.FarmerWSPort = origWS })
	defer startTestBus(t)()
	store.rows["ek_1"] = &enrollmentKeyRow{
		TenantID: "t_1", KeyHash: hashSecret("supersecret"),
		Expiry: time.Now().Add(time.Hour), MaxUses: 1,
	}
	setupSproutFiles(t)
	config.SproutRootCA = config.RootCA
	srv := startEnrollServer(t)
	wsURL := "wss://" + config.FarmerInterface + ":" + strconv.Itoa(wsPort)
	srv.setNatsURLs(wsURL)

	boxPub, err := EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := EnrollSprout(t.Context(), "ek_1.supersecret", "web-01", boxPub)
	if err != nil {
		t.Fatalf("EnrollSprout: %v", err)
	}
	if err := PersistEnrollment(resp); err != nil {
		t.Fatalf("PersistEnrollment: %v", err)
	}

	connect := func(t *testing.T, wantSource BusURLSource, wantScheme string) {
		t.Helper()
		b, err := LoadSproutBus()
		if err != nil {
			t.Fatal(err)
		}
		if b.Source != wantSource {
			t.Fatalf("source %q, want %q", b.Source, wantSource)
		}
		nc, err := b.Connect(nats.NoReconnect(), nats.Timeout(5*time.Second))
		if err != nil {
			t.Fatalf("connect to %q: %v", b.Servers, err)
		}
		defer nc.Close()
		if !strings.HasPrefix(nc.ConnectedUrl(), wantScheme+"://") {
			t.Errorf("connected to %q, want a %s:// URL", nc.ConnectedUrl(), wantScheme)
		}
		subj := "imas.sprouts." + resp.SproutID + ".facts"
		sub, err := nc.SubscribeSync(subj)
		if err != nil {
			t.Fatal(err)
		}
		if err := nc.Publish(subj, []byte("hello")); err != nil {
			t.Fatal(err)
		}
		if msg, err := sub.NextMsg(5 * time.Second); err != nil || string(msg.Data) != "hello" {
			t.Fatalf("round trip: msg=%v err=%v", msg, err)
		}
	}

	t.Run("enrolled nats_urls over wss", func(t *testing.T) {
		connect(t, BusURLsFromEnrollment, "wss")
	})
	t.Run("busurls pin wins", func(t *testing.T) {
		config.BusURLs = []string{"tls://" + config.FarmerBusURL}
		defer func() { config.BusURLs = nil }()
		connect(t, BusURLsFromConfig, "tls")
	})
	// Both transports through each kind of proxy: the proxy sees one
	// tunnel per connection, to the bus address itself.
	for _, scheme := range []string{"http", "socks5"} {
		for _, auth := range []bool{false, true} {
			name := "through " + scheme + " proxy"
			if auth {
				name += " with credentials"
			}
			t.Run(name, func(t *testing.T) {
				p := startTestProxy(t, scheme, auth)
				setBusProxyURL(t, p.URL())
				connect(t, BusURLsFromEnrollment, "wss")
				config.BusURLs = []string{"tls://" + config.FarmerBusURL}
				defer func() { config.BusURLs = nil }()
				connect(t, BusURLsFromConfig, "tls")
				want := []string{strings.TrimPrefix(wsURL, "wss://"), config.FarmerBusURL}
				if got := p.targets(); !reflect.DeepEqual(got, want) {
					t.Errorf("proxy tunnelled to %q, want %q", got, want)
				}
			})
		}
	}
	t.Run("legacy FarmerBusURL without enrolled URLs", func(t *testing.T) {
		if err := os.Remove(config.SproutBusURLsFile); err != nil {
			t.Fatal(err)
		}
		connect(t, BusURLsFromLegacy, "tls")
	})
}

func TestValidateBusProxyURL(t *testing.T) {
	ok := map[string]string{
		"":                                 "",
		"  ":                               "",
		"http://proxy:3128":                "http://proxy:3128",
		" HTTP://proxy.example.com:3128/ ": "http://proxy.example.com:3128",
		"socks5://127.0.0.1:1080":          "socks5://127.0.0.1:1080",
		"SOCKS5://[::1]:1080":              "socks5://[::1]:1080",
		"http://user:pass@proxy:3128":      "http://user:pass@proxy:3128",
		"socks5://user@proxy:1080":         "socks5://user@proxy:1080",
		"http://u%40x:p%3Ass@proxy:3128":   "http://u%40x:p%3Ass@proxy:3128",
	}
	for in, want := range ok {
		u, err := ValidateBusProxyURL(in)
		if err != nil {
			t.Errorf("ValidateBusProxyURL(%q): %v", in, err)
			continue
		}
		got := ""
		if u != nil {
			got = u.String()
		}
		if got != want {
			t.Errorf("ValidateBusProxyURL(%q) = %q, want %q", in, got, want)
		}
	}

	bad := map[string]string{
		"https proxy":        "https://proxy:3128",
		"socks5h":            "socks5h://proxy:1080",
		"socks4":             "socks4://proxy:1080",
		"websocket":          "ws://proxy:3128",
		"file":               "file:///etc/passwd",
		"no scheme":          "proxy:3128",
		"no port":            "http://proxy",
		"port zero":          "http://proxy:0",
		"port out of range":  "socks5://proxy:65536",
		"no host":            "http://:3128",
		"path":               "http://proxy:3128/connect",
		"query":              "http://proxy:3128/?x=1",
		"empty query":        "http://proxy:3128/?",
		"fragment":           "http://proxy:3128#x",
		"password only":      "http://:pw@proxy:3128",
		"colon in username":  "http://u%3Ax:pw@proxy:3128",
		"long username":      "socks5://" + strings.Repeat("u", maxProxyCredentialLength+1) + "@proxy:1080",
		"long password":      "socks5://u:" + strings.Repeat("p", maxProxyCredentialLength+1) + "@proxy:1080",
		"too long":           "http://" + strings.Repeat("a", maxBusProxyURLLength) + ":1",
		"unparseable":        "http://pro xy:3128",
		"bad percent escape": "http://u:%zz@proxy:3128",
	}
	for name, in := range bad {
		if _, err := ValidateBusProxyURL(in); err == nil {
			t.Errorf("%s: ValidateBusProxyURL(%q) accepted", name, in)
		}
	}

	// No error echoes the proxy password, whatever the reason.
	for _, in := range []string{
		"http://u:secretpw@proxy",
		"ftp://u:secretpw@proxy:21",
		"http://u:secretpw@proxy:3128/path",
		"http://u:secretpw@pro xy:3128",
		"http://u:secretpw%zz@proxy:3128",
	} {
		if _, err := ValidateBusProxyURL(in); err == nil || strings.Contains(err.Error(), "secretpw") {
			t.Errorf("ValidateBusProxyURL(%q): error should not echo the password: %v", in, err)
		}
	}
}

func setBusProxyURL(t *testing.T, u string) {
	t.Helper()
	old := config.BusProxyURL
	t.Cleanup(func() { config.BusProxyURL = old })
	config.BusProxyURL = u
}

func TestLoadSproutBus_Proxy(t *testing.T) {
	setupTestPKI(t)
	setupSproutFiles(t)
	config.SproutRootCA = config.RootCA
	if err := os.WriteFile(config.SproutUserJWTFile, []byte("user.jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	busPort := envoytest.FreePort(t) // nothing listens there
	config.BusURLs = []string{"tls://localhost:" + strconv.Itoa(busPort)}

	setBusProxyURL(t, "ftp://proxy:21")
	if _, err := LoadSproutBus(); err == nil || !strings.Contains(err.Error(), "busproxyurl") {
		t.Fatalf("invalid busproxyurl: err = %v", err)
	}

	p := startTestProxy(t, "socks5", true)
	setBusProxyURL(t, p.URL())
	b, err := LoadSproutBus()
	if err != nil {
		t.Fatal(err)
	}
	if b.Proxy != "socks5://"+p.ln.Addr().String() {
		t.Errorf("Proxy = %q, want the proxy URL without credentials", b.Proxy)
	}
	o := appliedOptions(t, b)
	if _, ok := o.CustomDialer.(*busProxyDialer); !ok || !o.SkipHostLookup {
		t.Fatalf("CustomDialer %T, SkipHostLookup %v: want the proxy dialer and no local lookup", o.CustomDialer, o.SkipHostLookup)
	}
	if !o.Secure || o.TLSConfig == nil || o.TLSConfig.RootCAs == nil || !o.IgnoreDiscoveredServers {
		t.Error("the proxy replaced the bus's TLS or discovery options instead of adding to them")
	}

	// The proxy is handed the bus hostname as configured, not addresses
	// resolved on the sprout. (Nothing listens on busPort, so the
	// proxy's own dial fails.)
	if nc, err := b.Connect(nats.NoReconnect(), nats.Timeout(5*time.Second)); err == nil {
		nc.Close()
		t.Fatal("connected to a bus that isn't there")
	} else if strings.Contains(err.Error(), p.pass) {
		t.Errorf("connect error echoes the proxy password: %v", err)
	}
	if got, want := p.targets(), []string{"localhost:" + strconv.Itoa(busPort)}; !reflect.DeepEqual(got, want) {
		t.Errorf("proxy asked for %q, want %q", got, want)
	}
}

func TestBusProxyTimeout(t *testing.T) {
	d := &busProxyDialer{proxy: &url.URL{Scheme: "http", Host: "proxy:3128"}}
	o := nats.GetDefaultOptions()
	for _, opt := range []nats.Option{nats.SetCustomDialer(d), nats.Timeout(7 * time.Second), busProxyTimeout} {
		if err := opt(&o); err != nil {
			t.Fatal(err)
		}
	}
	got, ok := o.CustomDialer.(*busProxyDialer)
	if !ok || got.timeout != 7*time.Second {
		t.Fatalf("dialer %#v: want the connection's 7s timeout", o.CustomDialer)
	}
	if d.timeout != 0 {
		t.Error("busProxyTimeout modified the SproutBus's shared dialer")
	}

	// A caller's own dialer is left alone.
	o.CustomDialer = &net.Dialer{}
	if err := busProxyTimeout(&o); err != nil {
		t.Fatal(err)
	}
	if _, ok := o.CustomDialer.(*net.Dialer); !ok {
		t.Error("busProxyTimeout replaced a dialer that isn't the bus proxy's")
	}
}

func TestBusProxyDialer_Rejected(t *testing.T) {
	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			p := startTestProxy(t, scheme, true)
			target := p.ln.Addr().String() // anything; the proxy refuses first
			for name, user := range map[string]*url.Userinfo{
				"no credentials": nil,
				"wrong password": url.UserPassword(p.user, "wrongpw"),
			} {
				u := &url.URL{Scheme: scheme, Host: p.ln.Addr().String(), User: user}
				d := &busProxyDialer{proxy: u, timeout: 5 * time.Second}
				conn, err := d.Dial("tcp", target)
				if err == nil {
					conn.Close()
					t.Errorf("%s: proxy accepted", name)
					continue
				}
				if strings.Contains(err.Error(), "wrongpw") {
					t.Errorf("%s: error echoes the password: %v", name, err)
				}
			}
			if got := p.targets(); len(got) != 0 {
				t.Errorf("proxy tunnelled to %q without valid credentials", got)
			}

			// Right credentials, but the proxy can't reach the target.
			u := &url.URL{Scheme: scheme, Host: p.ln.Addr().String(), User: url.UserPassword(p.user, p.pass)}
			d := &busProxyDialer{proxy: u, timeout: 5 * time.Second}
			if conn, err := d.Dial("tcp", "127.0.0.1:"+strconv.Itoa(envoytest.FreePort(t))); err == nil {
				conn.Close()
				t.Error("dial to an unreachable target succeeded")
			}
		})
	}
}

func TestBusProxyDialer_Timeout(t *testing.T) {
	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			// A proxy that accepts and never answers.
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					t.Cleanup(func() { c.Close() })
				}
			}()
			d := &busProxyDialer{proxy: &url.URL{Scheme: scheme, Host: ln.Addr().String()}, timeout: 200 * time.Millisecond}
			start := time.Now()
			if conn, err := d.Dial("tcp", "bus:4222"); err == nil {
				conn.Close()
				t.Fatal("dial through a silent proxy succeeded")
			}
			if elapsed := time.Since(start); elapsed > 3*time.Second {
				t.Errorf("dial took %v, want about the 200ms timeout", elapsed)
			}
		})
	}
}

// A tls:// or nats:// bus sends INFO before the client says anything, so
// its first bytes can arrive in the same read as the proxy's CONNECT
// response; they must not be lost.
func TestBusProxyDialer_HTTPKeepsBytesAfterResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
			return
		}
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\nINFO {}\r\n"))
		io.Copy(io.Discard, c)
	}()
	d := &busProxyDialer{proxy: &url.URL{Scheme: "http", Host: ln.Addr().String()}, timeout: 5 * time.Second}
	conn, err := d.Dial("tcp", "bus:4222")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || got != "INFO {}\r\n" {
		t.Fatalf("first read through the tunnel: %q, %v", got, err)
	}
}

// testProxy is a minimal in-process HTTP CONNECT or SOCKS5 (RFC 1928,
// with RFC 1929 username/password when auth is set) proxy that records
// the target of each tunnel it opens.
type testProxy struct {
	ln         net.Listener
	scheme     string
	user, pass string

	mu   sync.Mutex
	seen []string
}

func startTestProxy(t *testing.T, scheme string, auth bool) *testProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &testProxy{ln: ln, scheme: scheme}
	if auth {
		p.user, p.pass = "sprout", "pr0xy-secret"
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p
}

// URL is the proxy's busproxyurl, with its credentials if it wants them.
func (p *testProxy) URL() string {
	u := url.URL{Scheme: p.scheme, Host: p.ln.Addr().String()}
	if p.user != "" {
		u.User = url.UserPassword(p.user, p.pass)
	}
	return u.String()
}

func (p *testProxy) targets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

func (p *testProxy) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	var up net.Conn
	if p.scheme == "http" {
		up = p.handshakeHTTP(c, br)
	} else {
		up = p.handshakeSOCKS5(c, br)
	}
	if up == nil {
		return
	}
	defer up.Close()
	c.SetDeadline(time.Time{})
	go func() {
		io.Copy(up, br)
		up.Close()
	}()
	io.Copy(c, up)
}

func (p *testProxy) dialTarget(target string) net.Conn {
	p.mu.Lock()
	p.seen = append(p.seen, target)
	p.mu.Unlock()
	up, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return nil
	}
	return up
}

func (p *testProxy) handshakeHTTP(c net.Conn, br *bufio.Reader) net.Conn {
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return nil
	}
	if p.user != "" {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(p.user+":"+p.pass))
		if req.Header.Get("Proxy-Authorization") != want {
			io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 0\r\n\r\n")
			return nil
		}
	}
	up := p.dialTarget(req.Host)
	if up == nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return nil
	}
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	return up
}

func (p *testProxy) handshakeSOCKS5(c net.Conn, br *bufio.Reader) net.Conn {
	readN := func(n int) []byte {
		b := make([]byte, n)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil
		}
		return b
	}
	hdr := readN(2)
	if hdr == nil || hdr[0] != 5 {
		return nil
	}
	methods := readN(int(hdr[1]))
	method := byte(0x00)
	if p.user != "" {
		method = 0x02
	}
	if !bytes.Contains(methods, []byte{method}) {
		c.Write([]byte{5, 0xff})
		return nil
	}
	c.Write([]byte{5, method})
	if method == 0x02 {
		v := readN(2)
		if v == nil || v[0] != 1 {
			return nil
		}
		user := readN(int(v[1]))
		plen := readN(1)
		if user == nil || plen == nil {
			return nil
		}
		pass := readN(int(plen[0]))
		if string(user) != p.user || string(pass) != p.pass {
			c.Write([]byte{1, 1})
			return nil
		}
		c.Write([]byte{1, 0})
	}
	req := readN(4)
	if req == nil || req[0] != 5 || req[1] != 1 { // CONNECT only
		return nil
	}
	var host string
	switch req[3] {
	case 1:
		host = net.IP(readN(4)).String()
	case 3:
		l := readN(1)
		if l == nil {
			return nil
		}
		host = string(readN(int(l[0])))
	case 4:
		host = net.IP(readN(16)).String()
	default:
		return nil
	}
	port := readN(2)
	if port == nil {
		return nil
	}
	up := p.dialTarget(net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))))
	if up == nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // connection refused
		return nil
	}
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	return up
}
