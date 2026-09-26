package saasapi

import (
	"context"
	"math"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"
	"golang.org/x/time/rate"

	log "github.com/yogzblr/imas/internal/log"
)

// valkeyLimiterKeyPrefix namespaces this service's rate-limit keys, in
// the same "imas:<area>:" style as internal/heartbeat's keys, so the
// limiter can share farmer's Valkey without colliding with anything.
const valkeyLimiterKeyPrefix = "imas:saasapi:ratelimit:"

// valkeyLimiterTimeout bounds one limiter round trip. An in-cluster
// Valkey answers in about a millisecond; if it takes longer than this,
// the request falls back to the per-pod limiter rather than stalling.
const valkeyLimiterTimeout = 250 * time.Millisecond

// gcraScript is the shared rate limit, run atomically inside Valkey so
// every pod sees the same state. It implements GCRA (the generic cell
// rate algorithm), which admits exactly the same traffic as a token
// bucket (rate r, burst b) but needs only one value per caller: the
// "theoretical arrival time" (TAT) of the next request.
//
//   - Time comes from Valkey's own TIME, not the calling pod's clock, so
//     clock skew between pods can't loosen the limit.
//   - Times are whole milliseconds: Lua numbers are doubles, and a
//     millisecond Unix time (13 digits) survives the number-to-string
//     conversion SET does exactly on every Lua implementation, which a
//     microsecond one (16 digits) does not.
//   - The key expires when the bucket would be full again, so idle
//     callers cost nothing and nothing needs evicting.
//
// KEYS[1]: the caller's key. ARGV[1]: emission interval (ms per
// request, 1/rate). ARGV[2]: burst. Returns 1 if the request is allowed.
const gcraScript = `
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local interval = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])

local tat = tonumber(redis.call('GET', KEYS[1]))
if tat == nil or tat < now then
  tat = now
end

local new_tat = tat + interval
if new_tat - burst * interval > now then
  return 0
end

redis.call('SET', KEYS[1], new_tat, 'PX', new_tat - now)
return 1
`

var gcra = valkey.NewLuaScript(gcraScript)

// valkeyLimiter is a callerLimiter whose buckets live in Valkey, so the
// limit holds across every saasapi pod instead of per pod.
//
// If Valkey errors or times out, the request is decided by a per-pod
// perCallerLimiter with the same rate and burst instead. That keeps
// enrollment-key issuance available during a Valkey outage while still
// bounding it (at up to N times the limit across N pods, the same as
// running without Valkey at all), rather than either failing every
// request or dropping the limit entirely.
type valkeyLimiter struct {
	client     valkey.Client
	name       string
	intervalMS int64
	burst      int
	fallback   *perCallerLimiter
}

// NewValkeyLimiter builds a shared limiter allowing r events/second
// sustained, with bursts up to burst, per caller key, stored in client.
// name namespaces its keys (e.g. "enrollment-keys") so several limiters
// can share one Valkey.
//
// State is kept in whole milliseconds (see gcraScript), so the fastest
// rate it can express is 1000 events/second per key; a higher r is
// treated as 1000. That is far above anything the endpoints it guards
// need. At the other end, a rate slower than one event a day is treated
// as one a day, which keeps the millisecond arithmetic well inside what
// a Lua number holds exactly.
func NewValkeyLimiter(client valkey.Client, name string, r rate.Limit, burst int) *valkeyLimiter {
	const maxIntervalMS = 24 * 60 * 60 * 1000
	ms := math.Round(1000 / float64(r))
	interval := int64(maxIntervalMS)
	if ms < maxIntervalMS {
		interval = max(int64(ms), 1)
	}
	return &valkeyLimiter{
		client:     client,
		name:       name,
		intervalMS: interval,
		burst:      burst,
		fallback:   NewPerCallerLimiter(r, burst),
	}
}

func (l *valkeyLimiter) allow(ctx context.Context, key string) bool {
	ok, err := l.allowShared(ctx, key)
	if err != nil {
		log.Warnf("saasapi: rate limiter %q: Valkey unavailable, using this pod's own limit for %q: %v", l.name, key, err)
		return l.fallback.allow(ctx, key)
	}
	return ok
}

func (l *valkeyLimiter) allowShared(ctx context.Context, key string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, valkeyLimiterTimeout)
	defer cancel()

	n, err := gcra.Exec(ctx, l.client,
		[]string{valkeyLimiterKeyPrefix + l.name + ":" + key},
		[]string{strconv.FormatInt(l.intervalMS, 10), strconv.Itoa(l.burst)},
	).AsInt64()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}
