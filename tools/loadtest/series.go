package main

import (
	"encoding/json"
	"strconv"
	"sync"
	"time"
)

// series counts events per wall-clock second (Unix seconds), so series
// from several load generators with synchronised clocks add up.
type series struct {
	mu sync.Mutex
	m  map[int64]int
}

func newSeries() *series { return &series{m: map[int64]int{}} }

func (s *series) Add(t time.Time, n int) {
	s.mu.Lock()
	s.m[t.Unix()] += n
	s.mu.Unlock()
}

// Peak is the largest count in any one second.
func (s *series) Peak() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := 0
	for _, v := range s.m {
		p = max(p, v)
	}
	return p
}

// PeakBetween is Peak over the seconds in [from, to].
func (s *series) PeakBetween(from, to time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := 0
	for k, v := range s.m {
		if k >= from.Unix() && k <= to.Unix() {
			p = max(p, v)
		}
	}
	return p
}

// SumBetween is the total over the seconds in [from, to].
func (s *series) SumBetween(from, to time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, v := range s.m {
		if k >= from.Unix() && k <= to.Unix() {
			n += v
		}
	}
	return n
}

// Between returns a copy holding only the seconds in [from, to].
func (s *series) Between(from, to time.Time) *series {
	out := newSeries()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if k >= from.Unix() && k <= to.Unix() {
			out.m[k] = v
		}
	}
	return out
}

// Merge adds o's counts to s.
func (s *series) Merge(o *series) {
	if o == nil {
		return
	}
	o.mu.Lock()
	cp := make(map[int64]int, len(o.m))
	for k, v := range o.m {
		cp[k] = v
	}
	o.mu.Unlock()
	s.mu.Lock()
	for k, v := range cp {
		s.m[k] += v
	}
	s.mu.Unlock()
}

func (s *series) MarshalJSON() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.m))
	for k, v := range s.m {
		out[strconv.FormatInt(k, 10)] = v
	}
	return json.Marshal(out)
}

func (s *series) UnmarshalJSON(b []byte) error {
	var in map[string]int
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	s.m = make(map[int64]int, len(in))
	for k, v := range in {
		sec, err := strconv.ParseInt(k, 10, 64)
		if err != nil {
			return err
		}
		s.m[sec] = v
	}
	return nil
}
