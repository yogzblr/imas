package client

// Following cook step events over the sealed farmer-to-CLI leg (U3;
// internal/natsapi's jobsfollow.go). FLAG FOR SECURITY REVIEW.
//
// The CLI holds no tenant key and never reads imas.cook.* itself. It
// subscribes on a stream subject of its own choosing, then asks farmer,
// with the sealed jobs.follow request, to forward the job's events there.
// It accepts only an f2c.cook.step message that opens under its CLI box
// key, from its pinned tenant key, for this user, answering that request
// (pki.CLIOpenEvent), fresh, naming this stream, and not seen before on
// it. Everything else is dropped, plaintext included.

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// MethodJobsFollow is farmer's jobs.follow (internal/natsapi).
const MethodJobsFollow = "jobs.follow"

// FollowOptions bound a follow. Idle ends it after that long without an
// event (0 for no idle limit); Max ends it in any case (0 for farmer's
// maximum, 35 minutes).
type FollowOptions struct {
	Idle, Max time.Duration
}

// StepStream is a running follow. Events delivers each step event once,
// in the order farmer forwarded it; it is closed by Stop.
type StepStream struct {
	Events <-chan cook.FollowedStepEvent

	sub      *nats.Subscription
	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// Stop ends the stream on this side and closes Events. Farmer's side ends
// at its idle or maximum time.
func (s *StepStream) Stop() {
	s.stopOnce.Do(func() {
		_ = s.sub.Unsubscribe()
		close(s.stop)
	})
	<-s.done
}

// FollowJobs follows job jid's step events, or every job's the user may
// view if jid is empty, over nc. It returns once farmer is subscribed to
// them, so a cook triggered after it misses none.
func FollowJobs(nc *nats.Conn, jid string, opts FollowOptions) (*StepStream, error) {
	if nc == nil {
		return nil, errors.New("NATS connection not established")
	}
	stream, err := payloadbox.NewID()
	if err != nil {
		return nil, err
	}
	subject := cook.FollowSubject(stream)
	raw := make(chan *nats.Msg, 4096)
	sub, err := nc.ChanSubscribe(subject, raw)
	if err != nil {
		return nil, err
	}
	if err := nc.Flush(); err != nil {
		_ = sub.Unsubscribe()
		return nil, err
	}
	params := map[string]any{"jid": jid, "stream": stream,
		"idle_seconds": int(opts.Idle / time.Second), "max_seconds": int(opts.Max / time.Second)}
	_, reqID, err := sealedRequest(nc, payloadbox.PurposeCLIRequest, MethodJobsFollow, params, NatsRequestTimeout)
	if err != nil {
		_ = sub.Unsubscribe()
		return nil, err
	}
	events := make(chan cook.FollowedStepEvent, 256)
	s := &StepStream{Events: events, sub: sub, stop: make(chan struct{}), done: make(chan struct{})}
	go s.run(raw, events, reqID, subject)
	return s, nil
}

func (s *StepStream) run(raw <-chan *nats.Msg, events chan<- cook.FollowedStepEvent, reqID, subject string) {
	defer close(s.done)
	defer close(events)
	seen := map[string]bool{}
	for {
		select {
		case <-s.stop:
			return
		case m := <-raw:
			ev, err := openFollowedEvent(reqID, subject, m)
			if err != nil {
				log.Debugf("follow: dropping a message on %s: %v", subject, err)
				continue
			}
			if seen[ev.EventID] {
				continue
			}
			seen[ev.EventID] = true
			select {
			case events <- *ev:
			case <-s.stop:
				return
			}
		}
	}
}

// openFollowedEvent opens m, a message on the stream subject that
// answers reqID.
func openFollowedEvent(reqID, subject string, m *nats.Msg) (*cook.FollowedStepEvent, error) {
	if m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		return nil, ErrPlaintextReply
	}
	msg, err := pki.CLIOpenEvent(payloadbox.PurposeCLICookStep, reqID, m.Data)
	if err != nil {
		return nil, err
	}
	var ev cook.FollowedStepEvent
	if err := json.Unmarshal(msg.Body, &ev); err != nil {
		return nil, payloadbox.ErrOpen
	}
	if ev.Stream != subject || ev.EventID == "" {
		return nil, payloadbox.ErrOpen
	}
	return &ev, nil
}
