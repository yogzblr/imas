package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/yogzblr/imas/internal/facts"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/props"
)

// factsRepublishInterval is how often the sprout re-sends its system facts.
// Farmer stores each fact as a prop that expires props.DefaultPropTTL after
// it was written, so a sprout that published only once at startup lost its
// os, arch and version props five minutes later and recipes' `props "os"`
// rendered empty (found by UAT scenario R6). A third of the TTL keeps the
// props alive across two lost publishes.
const factsRepublishInterval = props.DefaultPropTTL / 3

// publisher is the part of *nats.Conn the facts loop uses.
type publisher interface {
	Publish(subject string, data []byte) error
}

// publishFacts collects this host's facts and publishes them on the sprout's
// own facts subject.
func publishFacts(p publisher, id string) error {
	sysFacts := facts.Collect()
	sysFacts.SproutID = id
	b, err := json.Marshal(sysFacts)
	if err != nil {
		return err
	}
	return p.Publish("imas.sprouts."+id+".facts", b)
}

// runFactsRepublisher re-publishes the facts every interval until ctx ends.
// The first publish is natsInit's, so this waits one interval before its
// own first.
func runFactsRepublisher(ctx context.Context, p publisher, id string, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := publishFacts(p, id); err != nil {
				log.Errorf("failed to republish system facts: %v", err)
			}
		}
	}
}
