package natsapi

// U3 (security review P6): cook step events reach the CLI only over the
// sealed farmer-to-CLI leg. FLAG FOR SECURITY REVIEW. The sprout side is
// a step event sealed as a sprout seals it, the farmer side the real
// Subscribe (jobs.follow through the sealed router), the CLI side the real
// client.FollowJobs.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/api/client"
	intauth "github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/rbac"
)

// followSprout is a sprout of t_1 with a box key on record.
type followSprout struct {
	t    *testing.T
	id   string
	priv *[32]byte
}

func newFollowSprout(t *testing.T, id string) *followSprout {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.RotateSproutBoxKey("t_1", id, base64.StdEncoding.EncodeToString(pub[:]), time.Hour); err != nil {
		t.Fatal(err)
	}
	return &followSprout{t: t, id: id, priv: priv}
}

// event is the sealed step event this sprout publishes for step of jid,
// sealed with priv (the sprout's own key unless a test forges one).
func (s *followSprout) event(jid string, step cook.StepCompletion, priv *[32]byte) *nats.Msg {
	s.t.Helper()
	tk, err := pki.GetTenantX25519PublicKey("t_1")
	if err != nil {
		s.t.Fatal(err)
	}
	tenantPub, _ := pki.DecodeBoxPubKey(tk)
	msg, err := payloadbox.NewMessage(payloadbox.PurposeCookStep, "t_1", s.id, "", cook.StepEvent{JobID: jid, Step: step})
	if err != nil {
		s.t.Fatal(err)
	}
	data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: priv}})
	if err != nil {
		s.t.Fatal(err)
	}
	m := nats.NewMsg(cook.StepEventSubject(s.id, jid))
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Data = data
	return m
}

// next waits for one event on s, or reports none within d.
func next(s *client.StepStream, d time.Duration) (cook.FollowedStepEvent, bool) {
	select {
	case ev, ok := <-s.Events:
		return ev, ok
	case <-time.After(d):
		return cook.FollowedStepEvent{}, false
	}
}

func TestJobsFollowSealedLeg(t *testing.T) {
	f := startSealedFarmer(t)
	newSealedCLIUser(t)
	web := newFollowSprout(t, "web-01")

	// What the bus sees on the stream subjects.
	var mu sync.Mutex
	var onBus []*nats.Msg
	busSub, err := f.nc.Subscribe(cook.FollowSubjectPrefix+">", func(m *nats.Msg) {
		mu.Lock()
		onBus = append(onBus, m)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer busSub.Unsubscribe()

	stream, err := client.FollowJobs(f.nc, "job-1", client.FollowOptions{Idle: time.Minute})
	if err != nil {
		t.Fatalf("FollowJobs: %v", err)
	}
	defer stream.Stop()

	honest := web.event("job-1", cook.StepCompletion{ID: "s1", CompletionStatus: cook.StepFailed, Changes: []string{"secret-note-7f3a"}, Error: errors.New("exit 3")}, web.priv)
	if err := f.nc.PublishMsg(honest); err != nil {
		t.Fatal(err)
	}
	ev, ok := next(stream, 5*time.Second)
	if !ok {
		t.Fatal("no event over the sealed leg")
	}
	if ev.SproutID != "web-01" || ev.JobID != "job-1" || ev.Step.ID != "s1" || ev.Step.CompletionStatus != cook.StepFailed ||
		ev.Step.Error == nil || ev.Step.Error.Error() != "exit 3" || len(ev.Step.Changes) != 1 {
		t.Fatalf("event %+v", ev)
	}

	// None of these reaches the CLI: a plaintext event, one sealed under a
	// key farmer has no record of, one for another job, and a replay.
	plain, _ := json.Marshal(cook.StepCompletion{ID: "s1", CompletionStatus: cook.StepCompleted})
	_ = f.nc.Publish(cook.StepEventSubject("web-01", "job-1"), plain)
	_, strangerPriv, _ := box.GenerateKey(rand.Reader)
	_ = f.nc.PublishMsg(web.event("job-1", cook.StepCompletion{ID: "s1", CompletionStatus: cook.StepCompleted}, strangerPriv))
	_ = f.nc.PublishMsg(web.event("job-2", cook.StepCompletion{ID: "x"}, web.priv))
	_ = f.nc.PublishMsg(honest)
	if ev, ok := next(stream, 300*time.Millisecond); ok {
		t.Fatalf("a forged, other-job or replayed event reached the CLI: %+v", ev)
	}

	// The bus saw only sealed messages, none carrying the step's content.
	mu.Lock()
	captured := append([]*nats.Msg(nil), onBus...)
	mu.Unlock()
	if len(captured) != 1 {
		t.Fatalf("farmer forwarded %d messages, want 1", len(captured))
	}
	if captured[0].Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 ||
		bytes.Contains(captured[0].Data, []byte("secret-note")) || bytes.Contains(captured[0].Data, []byte("exit 3")) {
		t.Fatalf("forwarded message isn't sealed: %v %q", captured[0].Header, captured[0].Data)
	}

	// On the CLI leg: a replayed forwarded message, plaintext, and a
	// forwarded message of another follow moved onto this stream are all
	// dropped.
	_ = f.nc.PublishMsg(captured[0])
	other, err := client.FollowJobs(f.nc, "job-3", client.FollowOptions{Idle: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Stop()
	if err := f.nc.PublishMsg(web.event("job-3", cook.StepCompletion{ID: "y"}, web.priv)); err != nil {
		t.Fatal(err)
	}
	if _, ok := next(other, 5*time.Second); !ok {
		t.Fatal("the second follow got nothing")
	}
	mu.Lock()
	moved := onBus[len(onBus)-1]
	mu.Unlock()
	mine := captured[0].Subject
	m := nats.NewMsg(mine)
	m.Header = moved.Header
	m.Data = moved.Data
	_ = f.nc.PublishMsg(m)
	fake, _ := json.Marshal(cook.FollowedStepEvent{Stream: mine, SproutID: "web-01", JobID: "job-1", EventID: "e", Step: cook.StepCompletion{ID: "s1", CompletionStatus: cook.StepCompleted}})
	_ = f.nc.Publish(mine, fake)
	if ev, ok := next(stream, 300*time.Millisecond); ok {
		t.Fatalf("a replayed, moved or plaintext message reached the CLI: %+v", ev)
	}
}

// Every job: a user sees the events of the sprouts their role lets them
// view, and only those.
func TestJobsFollowScope(t *testing.T) {
	f := startSealedFarmer(t)
	u := newSealedCLIUser(t)
	web, db := newFollowSprout(t, "web-01"), newFollowSprout(t, "db-01")
	rs := intauth.CurrentPolicy().Roles
	if err := rs.Register(&rbac.Role{Name: "web-viewer", Rules: []rbac.Rule{{Action: rbac.ActionView, Scope: "sprout:web-01"}}}); err != nil {
		t.Fatal(err)
	}
	intauth.CurrentPolicy().Users.Set(u.id, "web-viewer")
	for _, id := range []string{"web-01", "db-01"} {
		acceptFollowSprout(t, id)
	}

	stream, err := client.FollowJobs(f.nc, "", client.FollowOptions{Max: time.Minute})
	if err != nil {
		t.Fatalf("FollowJobs: %v", err)
	}
	defer stream.Stop()
	_ = f.nc.PublishMsg(db.event("job-db", cook.StepCompletion{ID: "d1"}, db.priv))
	_ = f.nc.PublishMsg(web.event("job-web", cook.StepCompletion{ID: "w1"}, web.priv))
	ev, ok := next(stream, 5*time.Second)
	if !ok || ev.SproutID != "web-01" {
		t.Fatalf("first event %+v (%v), want web-01's", ev, ok)
	}
	if ev, ok := next(stream, 300*time.Millisecond); ok {
		t.Fatalf("an event of a sprout outside the user's scope reached them: %+v", ev)
	}
}

// acceptFollowSprout accepts id in t_1, so scope checks see it.
func acceptFollowSprout(t *testing.T, id string) {
	t.Helper()
	nk := generateTestNKey(t)
	if err := pki.UnacceptNKey("t_1", id, nk); err != nil {
		t.Fatal(err)
	}
	if err := pki.AcceptNKey("t_1", id); err != nil && !strings.Contains(err.Error(), "push") {
		t.Fatal(err)
	}
}

// jobs.follow refuses a bad stream or job ID, and runs only through a
// sealed request.
func TestJobsFollowParams(t *testing.T) {
	c := apiCaller{TenantID: "t_1", UserID: "U", req: &sealedRequest{ID: "r"}}
	for _, p := range []JobsFollowParams{
		{Stream: "short"},
		{Stream: strings.Repeat("A", 32)},
		{Stream: strings.Repeat("a", 32), JID: "a.b"},
		{Stream: strings.Repeat("a", 32), JID: "*"},
		{Stream: strings.Repeat("a", 32), IdleSeconds: -1},
		{Stream: strings.Repeat("a", 32), IdleSeconds: MaxFollowSeconds + 1},
	} {
		b, _ := json.Marshal(p)
		if _, err := handleJobsFollow(c, b); err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
	b, _ := json.Marshal(JobsFollowParams{Stream: strings.Repeat("a", 32)})
	if _, err := handleJobsFollow(apiCaller{TenantID: "t_1", UserID: "U"}, b); err == nil {
		t.Error("a follow without a sealed request was accepted")
	}
	if IsMutatingMethod(MethodJobsFollow) != true {
		t.Error("jobs.follow must be claimed cluster-wide")
	}
	if natsActionMap[MethodJobsFollow] != rbac.ActionView {
		t.Error("jobs.follow must need view")
	}
}

// A follow ends at its idle time, and gives its slot back.
func TestJobsFollowEnds(t *testing.T) {
	f := startSealedFarmer(t)
	newSealedCLIUser(t)
	before := activeFollows.Load()
	stream, err := client.FollowJobs(f.nc, "job-idle", client.FollowOptions{Idle: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Stop()
	if activeFollows.Load() != before+1 {
		t.Fatalf("active follows %d, want %d", activeFollows.Load(), before+1)
	}
	deadline := time.Now().Add(5 * time.Second)
	for activeFollows.Load() != before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if activeFollows.Load() != before {
		t.Fatal("the idle follow did not end")
	}
}

// Timeouts above farmer's maximum are clamped by the client, not refused:
// imas cook --cook-timeout 3600 still follows its job.
func TestJobsFollowClampsLongTimeouts(t *testing.T) {
	f := startSealedFarmer(t)
	newSealedCLIUser(t)
	stream, err := client.FollowJobs(f.nc, "job-long", client.FollowOptions{Idle: 2 * time.Hour, Max: 3 * time.Hour})
	if err != nil {
		t.Fatalf("FollowJobs with timeouts over the maximum: %v", err)
	}
	stream.Stop()
	if client.MaxFollow != time.Duration(MaxFollowSeconds)*time.Second {
		t.Fatalf("client.MaxFollow %s, farmer's maximum %ds", client.MaxFollow, MaxFollowSeconds)
	}
}

// A role change reaches a running follow: once the user loses view on a
// sprout, its events stop within viewRecheck.
func TestJobsFollowRechecksView(t *testing.T) {
	f := startSealedFarmer(t)
	u := newSealedCLIUser(t)
	web := newFollowSprout(t, "web-01")
	acceptFollowSprout(t, "web-01")
	acceptFollowSprout(t, "db-01")
	rs := intauth.CurrentPolicy().Roles
	for _, r := range []*rbac.Role{
		{Name: "web-viewer", Rules: []rbac.Rule{{Action: rbac.ActionView, Scope: "sprout:web-01"}}},
		{Name: "db-viewer", Rules: []rbac.Rule{{Action: rbac.ActionView, Scope: "sprout:db-01"}}},
	} {
		if err := rs.Register(r); err != nil {
			t.Fatal(err)
		}
	}
	intauth.CurrentPolicy().Users.Set(u.id, "web-viewer")
	orig := viewRecheck
	viewRecheck = 50 * time.Millisecond
	t.Cleanup(func() { viewRecheck = orig })

	stream, err := client.FollowJobs(f.nc, "", client.FollowOptions{Max: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Stop()
	_ = f.nc.PublishMsg(web.event("job-a", cook.StepCompletion{ID: "w1"}, web.priv))
	if _, ok := next(stream, 5*time.Second); !ok {
		t.Fatal("no event while the user may view the sprout")
	}
	intauth.CurrentPolicy().Users.Set(u.id, "db-viewer")
	time.Sleep(2 * viewRecheck)
	_ = f.nc.PublishMsg(web.event("job-a", cook.StepCompletion{ID: "w2"}, web.priv))
	if ev, ok := next(stream, 500*time.Millisecond); ok {
		t.Fatalf("an event reached the user after they lost view on its sprout: %+v", ev)
	}
}
