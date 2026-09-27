package pki

import (
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
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
	t.Run("legacy FarmerBusURL without enrolled URLs", func(t *testing.T) {
		if err := os.Remove(config.SproutBusURLsFile); err != nil {
			t.Fatal(err)
		}
		connect(t, BusURLsFromLegacy, "tls")
	})
}
