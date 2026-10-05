package payloadbox

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

// controlCase is one control-plane boundary: who seals a request to whom
// under which purpose, and which purpose the answer comes back under.
type controlCase struct {
	name      string
	call      string // request (or async result) purpose
	reply     string // reply purpose; "" for a one-way result
	tenant    string
	principal string
	method    string
	subject   string
}

var controlCases = []controlCase{
	{"cli api", PurposeCLIRequest, PurposeCLIReply, testTenant, "UALICE", "jobs.list", "imas.api.jobs.list"},
	{"cli user key", PurposeCLIUserKeySubmit, PurposeCLIReply, testTenant, "UALICE", "auth.rotatekey", "imas.api.auth.rotatekey"},
	{"saas provision", PurposeSaaSTenantProvision, "", PlatformTenantID, PrincipalSaaSAPI, "tenant.provision", "internal.tenant.provision"},
	{"saas deprovision", PurposeSaaSTenantDeprovision, "", PlatformTenantID, PrincipalSaaSAPI, "tenant.deprovision", "internal.tenant.deprovision"},
	{"saas sprout action", PurposeSaaSSproutAction, PurposeSaaSSproutActionReply, PlatformTenantID, PrincipalSaaSAPI, "sprout.action", "internal.sprout.action"},
	{"provisioned result", PurposeSaaSTenantProvisioned, "", PlatformTenantID, PrincipalSaaSAPI, "tenant.provisioned", "internal.tenant.provisioned.job-1"},
	{"deprovisioned result", PurposeSaaSTenantDeprovisioned, "", PlatformTenantID, PrincipalSaaSAPI, "tenant.deprovisioned", "internal.tenant.deprovisioned.job-1"},
}

func expectFor(c controlCase) CallExpect {
	return CallExpect{Purpose: c.call, TenantID: c.tenant, Principal: c.principal, Method: c.method, Subject: c.subject}
}

// Every control-plane purpose round-trips: the requester seals to the
// responder, the responder opens with its own view of the same pairing,
// and a reply (where the boundary has one) comes back bound to the call.
func TestControlRoundTripEveryPurpose(t *testing.T) {
	for _, c := range controlCases {
		t.Run(c.name, func(t *testing.T) {
			farmerKey, peerKey := genKeys(t), genKeys(t)
			peerSide := KeyPair{PeerPub: farmerKey.pub, Priv: peerKey.priv}
			farmerSide := KeyPair{PeerPub: peerKey.pub, Priv: farmerKey.priv}
			// An f2a result goes the other way: farmer seals, the SaaS
			// API opens. The pairing is symmetric, so the same test
			// covers it with the two sides swapped.
			sealer, opener := peerSide, farmerSide
			if strings.HasPrefix(c.call, "f2a.") {
				sealer, opener = farmerSide, peerSide
			}
			data, id, err := SealCall(Call{
				Purpose: c.call, TenantID: c.tenant, Principal: c.principal,
				Method: c.method, Subject: c.subject, Params: map[string]string{"k": "v"},
			}, []KeyPair{sealer})
			if err != nil {
				t.Fatal(err)
			}
			msg, body, err := OpenCall(data, []KeyPair{opener}, expectFor(c))
			if err != nil {
				t.Fatalf("OpenCall: %v", err)
			}
			if msg.ID != id || string(body.Params) != `{"k":"v"}` {
				t.Fatalf("opened %+v %+v", msg, body)
			}
			if c.reply == "" {
				return
			}
			rdata, err := SealReply(Reply{
				Purpose: c.reply, TenantID: c.tenant, Principal: c.principal, ReplyTo: id,
				Method: c.method, Subject: c.subject, Result: []int{1, 2}, Error: "",
			}, []KeyPair{farmerSide})
			if err != nil {
				t.Fatal(err)
			}
			_, rb, err := OpenReply(rdata, []KeyPair{peerSide}, ReplyExpect{
				Purpose: c.reply, TenantID: c.tenant, Principal: c.principal, ReplyTo: id,
				Method: c.method, Subject: c.subject,
			})
			if err != nil {
				t.Fatalf("OpenReply: %v", err)
			}
			if string(rb.Result) != "[1,2]" {
				t.Fatalf("result %s", rb.Result)
			}
		})
	}
}

func TestOpenCallRefusals(t *testing.T) {
	farmerKey, alice, mallory := genKeys(t), genKeys(t), genKeys(t)
	c := controlCases[0]
	data, _, err := SealCall(Call{Purpose: c.call, TenantID: c.tenant, Principal: c.principal, Method: c.method, Subject: c.subject},
		[]KeyPair{{PeerPub: farmerKey.pub, Priv: alice.priv}})
	if err != nil {
		t.Fatal(err)
	}
	right := []KeyPair{{PeerPub: alice.pub, Priv: farmerKey.priv}}
	for _, tc := range []struct {
		name  string
		cands []KeyPair
		want  CallExpect
	}{
		// The header names alice but the key is mallory's: nothing a bus
		// could do with alice's ID makes mallory's key open her request.
		{"wrong key", []KeyPair{{PeerPub: mallory.pub, Priv: farmerKey.priv}}, expectFor(c)},
		{"wrong principal", right, func() CallExpect { e := expectFor(c); e.Principal = "UBOB"; return e }()},
		{"wrong method", right, func() CallExpect { e := expectFor(c); e.Method = "jobs.delete"; return e }()},
		{"wrong subject", right, func() CallExpect { e := expectFor(c); e.Subject = "imas.api.jobs.delete"; return e }()},
		{"wrong tenant", right, func() CallExpect { e := expectFor(c); e.TenantID = "t_b"; return e }()},
		{"wrong purpose", right, func() CallExpect { e := expectFor(c); e.Purpose = PurposeCLIUserKeySubmit; return e }()},
		{"empty method", right, func() CallExpect { e := expectFor(c); e.Method = ""; return e }()},
		{"empty subject", right, func() CallExpect { e := expectFor(c); e.Subject = ""; return e }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := OpenCall(data, tc.cands, tc.want); !errors.Is(err, ErrOpen) {
				t.Fatalf("got %v, want ErrOpen", err)
			}
		})
	}
	if _, _, err := OpenCall(data, right, expectFor(c)); err != nil {
		t.Fatalf("the untouched request must still open: %v", err)
	}
}

// A reply can't be taken for a call, nor a call for a reply, nor a reply
// for another request's.
func TestCallsAndRepliesDontCross(t *testing.T) {
	farmerKey, alice := genKeys(t), genKeys(t)
	cli := []KeyPair{{PeerPub: farmerKey.pub, Priv: alice.priv}}
	farmer := []KeyPair{{PeerPub: alice.pub, Priv: farmerKey.priv}}
	c := controlCases[0]
	call, id, err := SealCall(Call{Purpose: c.call, TenantID: c.tenant, Principal: c.principal, Method: c.method, Subject: c.subject}, cli)
	if err != nil {
		t.Fatal(err)
	}
	// The same purpose sealed as a reply (a purpose reuse bug) still
	// doesn't open as a call.
	asReply, err := SealReply(Reply{Purpose: c.call, TenantID: c.tenant, Principal: c.principal, ReplyTo: id, Method: c.method, Subject: c.subject}, cli)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenCall(asReply, farmer, expectFor(c)); !errors.Is(err, ErrOpen) {
		t.Errorf("a reply opened as a call: %v", err)
	}
	if _, _, err := OpenReply(call, farmer, ReplyExpect{Purpose: c.call, TenantID: c.tenant, Principal: c.principal, ReplyTo: id, Method: c.method, Subject: c.subject}); !errors.Is(err, ErrOpen) {
		t.Errorf("a call opened as a reply: %v", err)
	}
	reply, err := SealReply(Reply{Purpose: PurposeCLIReply, TenantID: c.tenant, Principal: c.principal, ReplyTo: id, Method: c.method, Subject: c.subject}, farmer)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := NewID()
	if _, _, err := OpenReply(reply, cli, ReplyExpect{Purpose: PurposeCLIReply, TenantID: c.tenant, Principal: c.principal, ReplyTo: other, Method: c.method, Subject: c.subject}); !errors.Is(err, ErrOpen) {
		t.Errorf("a reply to another request opened: %v", err)
	}
	if _, _, err := OpenReply(reply, cli, ReplyExpect{Purpose: PurposeCLIReply, TenantID: c.tenant, Principal: c.principal, ReplyTo: id, Method: "jobs.delete", Subject: c.subject}); !errors.Is(err, ErrOpen) {
		t.Errorf("a reply for another method opened: %v", err)
	}
	// Reflection: farmer's reply sent back to farmer as a request.
	if _, _, err := OpenCall(reply, farmer, expectFor(c)); !errors.Is(err, ErrOpen) {
		t.Errorf("a reflected reply opened as a call: %v", err)
	}
}

// A stale call opens (freshness is the receiver's), and ReplayGuard is
// what refuses it; a fresh one is accepted once.
func TestCallFreshnessIsTheGuards(t *testing.T) {
	farmerKey, alice := genKeys(t), genKeys(t)
	c := controlCases[0]
	defer func() { now = time.Now }()
	now = func() time.Time { return time.Now().Add(-10 * time.Minute) }
	stale, _, err := SealCall(Call{Purpose: c.call, TenantID: c.tenant, Principal: c.principal, Method: c.method, Subject: c.subject},
		[]KeyPair{{PeerPub: farmerKey.pub, Priv: alice.priv}})
	if err != nil {
		t.Fatal(err)
	}
	now = time.Now
	msg, _, err := OpenCall(stale, []KeyPair{{PeerPub: alice.pub, Priv: farmerKey.priv}}, expectFor(c))
	if err != nil {
		t.Fatal(err)
	}
	if err := NewReplayGuard().Accept(msg); !errors.Is(err, ErrStale) {
		t.Fatalf("stale call: %v, want ErrStale", err)
	}
}

func TestSealCallAndReplyNeedTheirBindings(t *testing.T) {
	k := genKeys(t)
	pairs := []KeyPair{{PeerPub: k.pub, Priv: k.priv}}
	if _, _, err := SealCall(Call{Purpose: PurposeCLIRequest, TenantID: testTenant, Principal: "U", Subject: "imas.api.x"}, pairs); err == nil {
		t.Error("a call without a method sealed")
	}
	if _, _, err := SealCall(Call{Purpose: PurposeCLIRequest, TenantID: testTenant, Principal: "U", Method: "x"}, pairs); err == nil {
		t.Error("a call without a subject sealed")
	}
	if _, err := SealReply(Reply{Purpose: PurposeCLIReply, TenantID: testTenant, Principal: "U", Method: "x", Subject: "imas.api.x"}, pairs); err == nil {
		t.Error("a reply without ReplyTo sealed")
	}
	if _, _, err := SealCall(Call{Purpose: PurposeCLIRequest, TenantID: testTenant, Principal: "U", Method: "x", Subject: "imas.api.x",
		Params: json.RawMessage(`{bad`)}, pairs); err == nil {
		t.Error("invalid raw params sealed")
	}
}

func TestControlPurposesAreDistinctAndDirected(t *testing.T) {
	all := []string{
		PurposeCmdRunRequest, PurposeCmdRunResponse, PurposeCookRequest, PurposeCookResponse,
		PurposeCookNudgeRequest, PurposeCookNudgeResponse, PurposeStagedRecipe, PurposeBoxKeySubmit, PurposeTenantKeyContinuity,
		PurposeEnrollProof,
		PurposeCLIRequest, PurposeCLIReply, PurposeCLIUserKeySubmit,
		PurposeSaaSTenantProvision, PurposeSaaSTenantDeprovision, PurposeSaaSSproutAction,
		PurposeSaaSTenantProvisioned, PurposeSaaSTenantDeprovisioned, PurposeSaaSSproutActionReply,
		PurposeRefresh, PurposeRefreshReply,
	}
	seen := map[string]bool{}
	for _, p := range all {
		if seen[p] {
			t.Errorf("purpose %q is used twice", p)
		}
		seen[p] = true
		dir, _, _ := strings.Cut(p, ".")
		switch dir {
		case "f2s", "s2f", "c2f", "f2c", "a2f", "f2a":
		default:
			t.Errorf("purpose %q doesn't name its direction", p)
		}
	}
	// internal/pki IsValidTenantID's alphabet: the platform marker must
	// never be a tenant's ID.
	if regexp.MustCompile(`^[0-9A-Za-z_-]{1,191}$`).MatchString(PlatformTenantID) {
		t.Errorf("PlatformTenantID %q could be a tenant ID", PlatformTenantID)
	}
}

func TestCheckPublicKeyRefusesLowOrderPoints(t *testing.T) {
	var zero [32]byte
	one := [32]byte{0: 1}
	// A point of order 8 (from the curve25519 small-subgroup list).
	order8 := [32]byte{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
		0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00}
	for name, k := range map[string]*[32]byte{"zero": &zero, "one": &one, "order 8": &order8, "nil": nil} {
		if err := CheckPublicKey(k); !errors.Is(err, ErrWeakKey) {
			t.Errorf("%s: %v, want ErrWeakKey", name, err)
		}
	}
	if err := CheckPublicKey(genKeys(t).pub); err != nil {
		t.Errorf("a real key: %v", err)
	}
}
