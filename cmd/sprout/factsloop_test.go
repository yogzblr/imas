package main

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/facts"
	"github.com/yogzblr/imas/internal/props"
)

type fakePub struct {
	mu   sync.Mutex
	subj []string
	data [][]byte
}

func (f *fakePub) Publish(s string, d []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subj = append(f.subj, s)
	f.data = append(f.data, d)
	return nil
}

func (f *fakePub) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subj)
}

func TestPublishFactsSubjectAndBody(t *testing.T) {
	p := &fakePub{}
	if err := publishFacts(p, "web-01"); err != nil {
		t.Fatal(err)
	}
	if p.subj[0] != "imas.sprouts.web-01.facts" {
		t.Fatalf("subject %q", p.subj[0])
	}
	var sf facts.SystemFacts
	if err := json.Unmarshal(p.data[0], &sf); err != nil {
		t.Fatal(err)
	}
	if sf.SproutID != "web-01" || sf.OS == "" {
		t.Fatalf("facts %+v", sf)
	}
}

func TestFactsRepublisherRepeatsAndStops(t *testing.T) {
	p := &fakePub{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runFactsRepublisher(ctx, p, "web-01", 10*time.Millisecond); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for p.count() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if p.count() < 3 {
		t.Fatalf("published %d times, want at least 3", p.count())
	}
}

func TestFactsRepublishBeatsPropTTL(t *testing.T) {
	if 2*factsRepublishInterval >= props.DefaultPropTTL {
		t.Fatalf("interval %v too long for TTL %v", factsRepublishInterval, props.DefaultPropTTL)
	}
}
