package main

import (
	"context"
	"errors"
	"time"

	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/facts"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/props"
)

// factsRepublishInterval is how often the sprout re-sends its system facts.
// Farmer stores each fact as a prop that expires props.DefaultPropTTL after
// it was written, so a sprout that published only once at startup lost its
// os, arch and version props five minutes later and recipes' `props "os"`
// rendered empty (found by UAT scenario R6). A third of the TTL keeps the
// props alive across two lost publishes.
const factsRepublishInterval = props.DefaultPropTTL / 3

// factsKeyWait is how often a sprout without payload-encryption keys
// checks again, so it sends its facts soon after it has them.
const factsKeyWait = 10 * time.Second

// publisher is the part of *nats.Conn the facts loop uses.
type publisher interface {
	PublishMsg(m *nats.Msg) error
}

// factsSubject is sprout id's facts subject.
func factsSubject(id string) string { return "imas.sprouts." + id + ".facts" }

// sealedFactsMsg collects this host's facts and seals them to farmer
// (payloadbox.PurposeFacts; security review P6), as a message for
// subject. Farmer refuses facts in plaintext, so a sprout without
// payload-encryption keys sends none: pki.ErrSproutBoxNotReady.
func sealedFactsMsg(subject, id string) (*nats.Msg, error) {
	if !pki.SproutBoxReady() {
		return nil, pki.ErrSproutBoxNotReady
	}
	sysFacts := facts.Collect()
	sysFacts.SproutID = id
	data, err := pki.SproutSealForFarmer(id, payloadbox.PurposeFacts, "", sysFacts)
	if err != nil {
		return nil, err
	}
	m := nats.NewMsg(subject)
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Data = data
	return m, nil
}

// publishFacts collects this host's facts and publishes them, sealed, on
// the sprout's own facts subject.
func publishFacts(p publisher, id string) error {
	m, err := sealedFactsMsg(factsSubject(id), id)
	if err != nil {
		return err
	}
	return p.PublishMsg(m)
}

// runFactsRepublisher publishes the facts at once and then every interval
// until ctx ends. While the sprout has no payload-encryption keys it
// publishes nothing and checks again every factsKeyWait, so its facts go
// out as soon as it has keys.
func runFactsRepublisher(ctx context.Context, p publisher, id string, interval time.Duration) {
	waiting := false
	for {
		next := interval
		switch err := publishFacts(p, id); {
		case err == nil:
			waiting = false
		case errors.Is(err, pki.ErrSproutBoxNotReady):
			if !waiting {
				log.Warnf("not sending system facts: this sprout has no payload-encryption keys yet, and farmer accepts only sealed facts; re-enroll it if this lasts")
			}
			waiting = true
			next = min(factsKeyWait, interval)
		default:
			log.Errorf("failed to publish system facts: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(next):
		}
	}
}

// answerFactsRequest answers an on-demand facts request with the same
// sealed report, or with the no-keys refusal on a sprout without keys:
// never with facts in plaintext.
func answerFactsRequest(m *nats.Msg, id string) {
	reply, err := sealedFactsMsg(m.Reply, id)
	if err != nil {
		reply = nats.NewMsg(m.Reply)
		code := payloadbox.ErrorCodeInternal
		if errors.Is(err, pki.ErrSproutBoxNotReady) {
			code = payloadbox.ErrorCodeNoKeys
		}
		reply.Header.Set(payloadbox.ErrorHeader, code)
		log.Warnf("facts.request: not answering with facts: %v", err)
	}
	if m.Reply == "" {
		return
	}
	if err := m.RespondMsg(reply); err != nil {
		log.Errorf("facts.request: sending reply: %v", err)
	}
}
