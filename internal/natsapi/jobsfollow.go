package natsapi

// jobs.follow: the sealed farmer-to-CLI leg for cook step events
// (security review P6, U3; docs/design/imas-payload-encryption-design.md,
// Decision 6 and "Sealing the control plane"). FLAG FOR SECURITY REVIEW.
//
// Sprouts seal their step events to the tenant key (internal/cook's
// stepevent.go), which the imas CLI and imas serve don't hold. A user who
// wants to watch a job (imas cook, imas jobs watch) or every job they may
// view (imas serve's log stream) asks farmer with this sealed request,
// naming a stream ID of their own choosing that they are already
// subscribed on (cook.FollowSubject). The replica that serves it
// subscribes, on the tenant's connection and outside the queue group, to
// the job's step events, and for each one that opens (cook.OpenStepEvent),
// is fresh and not a replay on this follow, and is from a sprout the
// user may view, forwards it on the stream as an f2c.cook.step message
// sealed to the user's active CLI box key, naming this request's ID
// (pki.SealEventToCLI). The bus sees ciphertext, can't forge or move an
// event, and can't redirect a stream: the stream ID travels sealed, and
// each forwarded event names its stream inside the box.
//
// A follow ends after IdleSeconds without a forwarded event (if set) or
// at MaxSeconds, whichever comes first, and the subscription is gone.
// Each replica runs at most maxFollows at once. The reply comes once the
// subscription is in place on the server, so a cook triggered after it
// misses no event.
//
// jobs.follow is not on readOnlyMethods (sealedapi.go): like a mutating
// method it is claimed cluster-wide, so a replayed request can't start a
// second follow on another replica. Its forwarded events are sealed to
// the requester either way.

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/cook"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/rbac"
)

// JobsFollowParams is jobs.follow's request.
type JobsFollowParams struct {
	// JID is the job to follow; empty follows every job of the tenant
	// whose sprout the user may view.
	JID string `json:"jid,omitempty"`
	// Stream is the stream ID (cook.ValidStreamID) the events go to, on
	// cook.FollowSubject(Stream).
	Stream string `json:"stream"`
	// IdleSeconds ends the follow after that long without an event; 0
	// for no idle limit. At most MaxFollowSeconds.
	IdleSeconds int `json:"idle_seconds,omitempty"`
	// MaxSeconds ends the follow after that long in any case; 0 or more
	// than MaxFollowSeconds means MaxFollowSeconds.
	MaxSeconds int `json:"max_seconds,omitempty"`
}

// JobsFollowResponse is jobs.follow's result.
type JobsFollowResponse struct {
	Stream    string    `json:"stream"`
	ExpiresAt time.Time `json:"expires_at"`
}

// MaxFollowSeconds bounds a follow's lifetime: a recipe times out on its
// sprout after cook.DefaultCookTimeout, and a client that wants longer
// follows again. internal/api/client's MaxFollow is the same bound.
const MaxFollowSeconds = int((cook.DefaultCookTimeout + 5*time.Minute) / time.Second)

// viewRecheck is how long a follow trusts its answer to "may this user
// view this sprout": after it, the next event from the sprout checks the
// user's role again, so a role change reaches a running follow within it
// (as the shell re-checks a session's grant). A variable so tests can
// shorten it.
var viewRecheck = 60 * time.Second

// maxFollows bounds how many follows one replica runs at once.
const maxFollows = 1024

// ErrTooManyFollows: this replica is already running maxFollows follows.
var ErrTooManyFollows = errors.New("jobs.follow: this farmer replica is following too many streams; try again later")

// activeFollows counts this replica's running follows.
var activeFollows atomic.Int64

// sealFollowEvent seals a forwarded event for the follower; a variable so
// tests can count seals.
var sealFollowEvent = pki.SealEventToCLI

func handleJobsFollow(c apiCaller, params json.RawMessage) (any, error) {
	var p JobsFollowParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	if !cook.ValidStreamID(p.Stream) {
		return nil, errors.New("jobs.follow: stream must be 32 lowercase hex digits")
	}
	if !cook.ValidFollowJobID(p.JID) {
		return nil, errors.New("jobs.follow: invalid jid")
	}
	if p.IdleSeconds < 0 || p.IdleSeconds > MaxFollowSeconds || p.MaxSeconds < 0 {
		return nil, fmt.Errorf("jobs.follow: idle_seconds must be 0 to %d, max_seconds 0 or more", MaxFollowSeconds)
	}
	if c.req == nil {
		return nil, errors.New("jobs.follow: needs a sealed request")
	}
	maxSeconds := p.MaxSeconds
	if maxSeconds == 0 || maxSeconds > MaxFollowSeconds {
		maxSeconds = MaxFollowSeconds
	}
	nc, err := tenantConn(c.TenantID)
	if err != nil {
		return nil, err
	}
	if activeFollows.Add(1) > maxFollows {
		activeFollows.Add(-1)
		return nil, ErrTooManyFollows
	}
	f := &follow{
		tenantID: c.TenantID, userID: c.UserID, reqID: c.req.ID, subject: cook.FollowSubject(p.Stream),
		nc: nc, guard: payloadbox.NewKeyedReplayGuard(),
		allowed: map[string]viewGrant{}, recheck: viewRecheck, events: make(chan struct{}, 1),
	}
	jid := p.JID
	if jid == "" {
		jid = "*"
	}
	sub, err := nc.Subscribe(cook.StepEventSubject("*", jid), f.handle)
	if err != nil {
		activeFollows.Add(-1)
		return nil, fmt.Errorf("jobs.follow: subscribing: %w", err)
	}
	if err := nc.Flush(); err != nil {
		_ = sub.Unsubscribe()
		activeFollows.Add(-1)
		return nil, fmt.Errorf("jobs.follow: subscribing: %w", err)
	}
	f.sub = sub
	expires := time.Now().Add(time.Duration(maxSeconds) * time.Second)
	go f.run(time.Duration(p.IdleSeconds)*time.Second, time.Duration(maxSeconds)*time.Second)
	return JobsFollowResponse{Stream: p.Stream, ExpiresAt: expires.UTC()}, nil
}

// follow is one running jobs.follow.
type follow struct {
	tenantID, userID, reqID, subject string
	nc                               *nats.Conn
	sub                              *nats.Subscription
	// guard drops a replayed event, keyed on (sprout, message ID).
	// Sharded (payloadbox.KeyedReplayGuard), so an every-job follow of a
	// busy tenant has room for every event in the window.
	guard *payloadbox.KeyedReplayGuard

	// events gets a token for each forwarded event, resetting the idle
	// timer.
	events chan struct{}

	// recheck is viewRecheck as the follow started.
	recheck time.Duration

	mu      sync.Mutex
	allowed map[string]viewGrant // sprout ID -> the user may view it, as of checked
}

// viewGrant is a follow's cached answer for one sprout.
type viewGrant struct {
	ok      bool
	checked time.Time
}

// run ends the follow at its idle or maximum time.
func (f *follow) run(idle, max time.Duration) {
	defer activeFollows.Add(-1)
	defer func() { _ = f.sub.Unsubscribe() }()
	deadline := time.NewTimer(max)
	defer deadline.Stop()
	var idleC <-chan time.Time
	var idleT *time.Timer
	if idle > 0 {
		idleT = time.NewTimer(idle)
		defer idleT.Stop()
		idleC = idleT.C
	}
	for {
		select {
		case <-deadline.C:
			return
		case <-idleC:
			return
		case <-f.events:
			if idleT != nil {
				if !idleT.Stop() {
					select {
					case <-idleT.C:
					default:
					}
				}
				idleT.Reset(idle)
			}
		}
	}
}

// mayView reports whether the user may view sproutID, checking the
// user's role at most once per viewRecheck per sprout.
func (f *follow) mayView(sproutID string) bool {
	f.mu.Lock()
	g, seen := f.allowed[sproutID]
	f.mu.Unlock()
	if seen && time.Since(g.checked) < f.recheck {
		return g.ok
	}
	ok := checkScopedAccess(f.tenantID, f.userID, rbac.ActionView, []string{sproutID}) == nil
	f.mu.Lock()
	f.allowed[sproutID] = viewGrant{ok: ok, checked: time.Now()}
	f.mu.Unlock()
	return ok
}

// handle forwards one step event, if it opens, is new on this follow and
// is from a sprout the user may view. A refused event is dropped and
// logged without its content.
func (f *follow) handle(m *nats.Msg) {
	ev, err := cook.OpenStepEvent(f.tenantID, m)
	if err != nil {
		log.Debugf("jobs.follow: not forwarding an event on %s: %v", m.Subject, err)
		return
	}
	if !f.mayView(ev.SproutID) {
		return
	}
	if err := f.guard.Accept(ev.Message(), ev.SproutID); err != nil {
		if errors.Is(err, payloadbox.ErrReplayGuardFull) {
			log.Warnf("jobs.follow: dropping an event of job %s for %s: the follow's replay guard is full", ev.JobID, f.userID)
			return
		}
		log.Debugf("jobs.follow: not forwarding an event on %s: %v", m.Subject, err)
		return
	}
	data, err := sealFollowEvent(f.tenantID, f.userID, payloadbox.PurposeCLICookStep, f.reqID, cook.FollowedStepEvent{
		Stream: f.subject, SproutID: ev.SproutID, JobID: ev.JobID, EventID: ev.EventID, Step: ev.Step,
	})
	if err != nil {
		log.Warnf("jobs.follow: sealing an event of job %s for %s: %v", ev.JobID, f.userID, err)
		return
	}
	out := nats.NewMsg(f.subject)
	out.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	out.Data = data
	if err := f.nc.PublishMsg(out); err != nil {
		log.Warnf("jobs.follow: forwarding an event of job %s: %v", ev.JobID, err)
		return
	}
	select {
	case f.events <- struct{}{}:
	default:
	}
}
