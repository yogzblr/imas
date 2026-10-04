package main

import (
	"encoding/json"
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"sync/atomic"
	"time"
)

// hist is a log-linear latency histogram in microseconds, safe for
// concurrent Record. Values below 64µs get a bucket each; above that,
// every power of two is split into 64 buckets, so a reported percentile
// is within about 1.6% of the true value. Two hists always share the
// same layout, so the results of several load generators merge exactly.
type hist struct {
	counts [histBuckets]atomic.Uint64
	n      atomic.Uint64
	sumUS  atomic.Uint64
	maxUS  atomic.Uint64
}

const (
	histSub     = 64
	histBuckets = histSub + 40*histSub // up to 2^46µs, about two years
)

func histIndex(us uint64) int {
	if us < histSub {
		return int(us)
	}
	shift := bits.Len64(us) - 7 // us>>shift is in [64, 128)
	idx := histSub + shift*histSub + int(us>>uint(shift)) - histSub
	if idx >= histBuckets {
		return histBuckets - 1
	}
	return idx
}

// histUpper is the largest value bucket idx holds.
func histUpper(idx int) uint64 {
	if idx < histSub {
		return uint64(idx)
	}
	shift := (idx - histSub) / histSub
	top := uint64((idx-histSub)%histSub + histSub)
	return (top+1)<<uint(shift) - 1
}

func (h *hist) Record(d time.Duration) {
	us := uint64(max(d.Microseconds(), 0))
	h.counts[histIndex(us)].Add(1)
	h.n.Add(1)
	h.sumUS.Add(us)
	for {
		m := h.maxUS.Load()
		if us <= m || h.maxUS.CompareAndSwap(m, us) {
			return
		}
	}
}

func (h *hist) Count() uint64 { return h.n.Load() }

func (h *hist) Max() time.Duration { return time.Duration(h.maxUS.Load()) * time.Microsecond }

func (h *hist) Mean() time.Duration {
	n := h.n.Load()
	if n == 0 {
		return 0
	}
	return time.Duration(h.sumUS.Load()/n) * time.Microsecond
}

// Quantile returns the smallest bucket bound below which at least q of
// the recorded values fall (capped at the maximum seen), or 0 when empty.
func (h *hist) Quantile(q float64) time.Duration {
	n := h.n.Load()
	if n == 0 {
		return 0
	}
	rank := uint64(math.Ceil(q * float64(n)))
	rank = min(max(rank, 1), n)
	var cum uint64
	for i := range h.counts {
		cum += h.counts[i].Load()
		if cum >= rank {
			return time.Duration(min(histUpper(i), h.maxUS.Load())) * time.Microsecond
		}
	}
	return h.Max()
}

// Merge adds o's values to h.
func (h *hist) Merge(o *hist) {
	if o == nil {
		return
	}
	for i := range o.counts {
		if c := o.counts[i].Load(); c > 0 {
			h.counts[i].Add(c)
		}
	}
	h.n.Add(o.n.Load())
	h.sumUS.Add(o.sumUS.Load())
	for {
		m, om := h.maxUS.Load(), o.maxUS.Load()
		if om <= m || h.maxUS.CompareAndSwap(m, om) {
			return
		}
	}
}

// histJSON is a hist's wire form: only non-empty buckets, keyed by index.
type histJSON struct {
	Buckets map[string]uint64 `json:"buckets"`
	Count   uint64            `json:"count"`
	SumUS   uint64            `json:"sum_us"`
	MaxUS   uint64            `json:"max_us"`
}

func (h *hist) MarshalJSON() ([]byte, error) {
	out := histJSON{Buckets: map[string]uint64{}, Count: h.n.Load(), SumUS: h.sumUS.Load(), MaxUS: h.maxUS.Load()}
	for i := range h.counts {
		if c := h.counts[i].Load(); c > 0 {
			out.Buckets[strconv.Itoa(i)] = c
		}
	}
	return json.Marshal(out)
}

func (h *hist) UnmarshalJSON(b []byte) error {
	var in histJSON
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	for k, c := range in.Buckets {
		i, err := strconv.Atoi(k)
		if err != nil || i < 0 || i >= histBuckets {
			return fmt.Errorf("histogram bucket %q out of range", k)
		}
		h.counts[i].Store(c)
	}
	h.n.Store(in.Count)
	h.sumUS.Store(in.SumUS)
	h.maxUS.Store(in.MaxUS)
	return nil
}
