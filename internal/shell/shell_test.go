package shell

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

func TestValidSessionID(t *testing.T) {
	id, _ := payloadbox.NewID()
	if !ValidSessionID(id) {
		t.Fatalf("payloadbox.NewID %q is not a valid session ID", id)
	}
	for _, bad := range []string{"", "abc", strings.ToUpper(id), id + "0", "0123456789abcdef0123456789abcdeg", "web.01.>", "*"} {
		if ValidSessionID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidShellPath(t *testing.T) {
	for _, ok := range []string{"", "/bin/sh", "/usr/local/bin/fish"} {
		if !ValidShellPath(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"sh", "bin/sh", "/bin/sh -c id", "/bin/sh\n", "/bin/\x00sh", "/" + strings.Repeat("a", 300)} {
		if ValidShellPath(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The s2f subjects are exactly what the sprout's User JWT grants, and
// sit outside its own Sub grant.
func TestSubjectsMatchGrants(t *testing.T) {
	sid := "0123456789abcdef0123456789abcdef"
	out := SproutOutSubject("web-01", sid)
	grant := pki.SproutShellPublishGrant("web-01")
	if !strings.HasPrefix(out, strings.TrimSuffix(grant, ">")) || SproutOutSubjectPrefix("web-01")+".>" != grant {
		t.Fatalf("s2f subject %q isn't covered by grant %q", out, grant)
	}
	if strings.HasPrefix(out, "imas.sprouts.web-01.") {
		t.Fatal("s2f subject is inside the sprout's own Sub grant")
	}
	if in := SproutInSubject("web-01", sid); !strings.HasPrefix(in, "imas.sprouts.web-01.") {
		t.Fatalf("f2s subject %q is outside the sprout's Sub grant", in)
	}
	if StartSubject("web-01") != "imas.sprouts.web-01.shell.start" {
		t.Fatal("start subject changed")
	}
	if CLISubject(sid, payloadbox.DirC2F) != "imas.shell.cli."+sid+".c2f" {
		t.Fatal("CLI subject changed")
	}
}

func TestParseEtcShells(t *testing.T) {
	got := parseEtcShells([]byte("# /etc/shells\n/bin/sh\n\n  /bin/bash  # login\nnologin\n/usr/bin/zsh\n"))
	want := []string{"/bin/sh", "/bin/bash", "/usr/bin/zsh"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPickShell(t *testing.T) {
	allowed := []string{"/bin/bash", "/bin/sh"}
	for _, c := range []struct {
		req, want string
		ok        bool
	}{
		{"", "/bin/sh", true},
		{"/bin/bash", "/bin/bash", true},
		{"/bin/zsh", "", false},
		{"bash", "", false},
	} {
		got, ok := pickShell(c.req, allowed)
		if ok != c.ok || ok && got != c.want {
			t.Errorf("pickShell(%q) = %q, %v", c.req, got, ok)
		}
	}
	if got, ok := pickShell("", []string{"/bin/bash"}); !ok || got != "/bin/bash" {
		t.Errorf("no /bin/sh: got %q %v", got, ok)
	}
	if _, ok := pickShell("", nil); ok {
		t.Error("an empty allow-list allowed a shell")
	}
}

func TestPolicyAllowList(t *testing.T) {
	dir := t.TempDir()
	orig := etcShells
	etcShells = filepath.Join(dir, "shells")
	t.Cleanup(func() { etcShells = orig })
	if err := os.WriteFile(etcShells, []byte("/bin/sh\n/bin/dash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := (SproutPolicy{}).allowedShells(); !slices.Equal(got, []string{"/bin/sh", "/bin/dash"}) {
		t.Fatalf("/etc/shells default: %q", got)
	}
	if got := (SproutPolicy{AllowedShells: []string{"/bin/bash", "relative"}}).allowedShells(); !slices.Equal(got, []string{"/bin/bash"}) {
		t.Fatalf("configured list: %q", got)
	}
	os.Remove(etcShells)
	if got := (SproutPolicy{}).allowedShells(); len(got) != 0 {
		t.Fatalf("unreadable /etc/shells allowed %q", got)
	}
	if (SproutPolicy{}).maxSessions() != DefaultSproutMaxSessions || (SproutPolicy{MaxSessions: 2}).maxSessions() != 2 {
		t.Fatal("max sessions default")
	}
	SetSproutPolicy(SproutPolicy{Disabled: true})
	t.Cleanup(func() { SetSproutPolicy(SproutPolicy{}) })
	if !CurrentSproutPolicy().Disabled {
		t.Fatal("policy not set")
	}
}

func TestTrackerLimitsAndTenantKeying(t *testing.T) {
	tr := NewTracker()
	add := func(tenant, sid, user string, l Limits) bool {
		return tr.TryAdd(&SessionInfo{TenantID: tenant, SessionID: sid, Pubkey: user, StartedAt: time.Now()}, l)
	}
	l := Limits{PerUser: 2, PerTenant: 3, PerReplica: 4}
	if !add("t1", "s1", "alice", l) || !add("t1", "s2", "alice", l) {
		t.Fatal("first two refused")
	}
	if add("t1", "s3", "alice", l) {
		t.Fatal("per-user limit not applied")
	}
	if !add("t1", "s3", "bob", l) {
		t.Fatal("bob refused")
	}
	if add("t1", "s4", "carol", l) {
		t.Fatal("per-tenant limit not applied")
	}
	// The same session ID in another tenant is another session.
	if !add("t2", "s1", "alice", l) {
		t.Fatal("same session ID in another tenant refused")
	}
	if add("t2", "s9", "dave", l) {
		t.Fatal("per-replica limit not applied")
	}
	if add("t1", "s1", "alice", Limits{}) {
		t.Fatal("duplicate key accepted")
	}
	if tr.Get(SessionKey{"t2", "s1"}) == nil || tr.Get(SessionKey{"t3", "s1"}) != nil {
		t.Fatal("Get isn't keyed on the tenant")
	}
	if tr.Remove(SessionKey{"t1", "s1"}) == nil || tr.Remove(SessionKey{"t1", "s1"}) != nil || tr.Active() != 3 || len(tr.List()) != 3 {
		t.Fatal("Remove")
	}
}

// A plaintext start is refused whether or not the sprout has keys, and a
// sealed one on a sprout without keys gets no-keys; nothing is spawned.
func TestSproutRefusesWithoutOpening(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows answers a plaintext start without keys with its old message")
	}
	origPriv, origPin := config.SproutBoxPrivFile, config.SproutTenantX25519PubFile
	t.Cleanup(func() { config.SproutBoxPrivFile, config.SproutTenantX25519PubFile = origPriv, origPin })
	dir := t.TempDir()
	config.SproutBoxPrivFile = filepath.Join(dir, "box.key")
	config.SproutTenantX25519PubFile = filepath.Join(dir, "tenant.pub")
	sp := NewSprout(nil, "web-01")

	plain := &nats.Msg{Data: []byte(`{"session_id":"x","shell":"/bin/sh"}`)}
	sealedNoKeys := nats.NewMsg("")
	sealedNoKeys.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	sealedNoKeys.Data = []byte(`{"v":2,"s":[]}`)

	check := func(name string, m *nats.Msg, want string) {
		t.Helper()
		reply, sess := sp.respond(m)
		if sess != nil || sp.Active() != 0 {
			t.Fatalf("%s: spawned", name)
		}
		if got := reply.Header.Get(payloadbox.ErrorHeader); got != want || len(reply.Data) != 0 {
			t.Fatalf("%s: answered %v %q, want %s", name, reply.Header, reply.Data, want)
		}
	}
	check("plaintext, no keys", plain, payloadbox.ErrorCodeEncryptionRequired)
	check("sealed, no keys", sealedNoKeys, payloadbox.ErrorCodeNoKeys)

	// With keys: plaintext still refused, garbage doesn't open.
	if _, err := pki.EnsureSproutBoxKey(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.SproutTenantX25519PubFile, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), 0o644); err != nil {
		t.Fatal(err)
	}
	check("plaintext, keys", plain, payloadbox.ErrorCodeEncryptionRequired)
	check("sealed garbage", sealedNoKeys, payloadbox.ErrorCodeOpenFailed)
}

func TestValidStart(t *testing.T) {
	eph, _ := payloadbox.NewEphemeralKey()
	msg := &payloadbox.Message{TenantID: "t_1"}
	good := StartBody{SessionID: "0123456789abcdef0123456789abcdef", FarmerEphPub: eph.PublicKey().Bytes(), Cols: 80, Rows: 24, User: StartUser{Pubkey: "U1"}}
	if !validStart(msg, &good) {
		t.Fatal("good start refused")
	}
	for name, mutate := range map[string]func(*StartBody){
		"session":   func(b *StartBody) { b.SessionID = "x" },
		"user":      func(b *StartBody) { b.User.Pubkey = "" },
		"eph":       func(b *StartBody) { b.FarmerEphPub = make([]byte, 32) },
		"short eph": func(b *StartBody) { b.FarmerEphPub = []byte{1} },
		"size":      func(b *StartBody) { b.Cols = 0 },
		"shell":     func(b *StartBody) { b.Shell = "sh" },
	} {
		b := good
		mutate(&b)
		if validStart(msg, &b) {
			t.Errorf("%s: accepted", name)
		}
	}
}
