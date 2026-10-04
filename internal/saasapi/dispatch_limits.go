package saasapi

// Concurrency of internal.sprout.action dispatch (security review 2026-10,
// M5; FLAG FOR SECURITY REVIEW). Before this, one 64-slot pool per process
// was shared by every tenant's §1.5 items and every rollout wave, and an
// item holds its slot until farmer replies (up to about 10m45s for a
// cmd.run with timeout_seconds 600). One tenant posting long cmd.runs
// could hold every slot and stall every other tenant's actions and every
// update rollout.
//
// Now each process has two pools:
//
//   - cmd.run and cook items (SAASAPI_ACTION_DISPATCH_CONCURRENCY,
//     default 64);
//   - self_update items, reserved for rollout waves
//     (SAASAPI_SELF_UPDATE_DISPATCH_CONCURRENCY, default 16), so no amount
//     of cmd.run, the same tenant's included, delays a rollout;
//
// and within each pool one tenant holds at most
// SAASAPI_ACTION_DISPATCH_TENANT_CONCURRENCY slots (default 8; at most
// half the cmd.run/cook pool, which LoadConfig enforces). A tenant over
// its cap waits for its own slots without holding a pool slot, so it
// delays only itself.
//
// Farmer has the same pools and caps per replica, with the same defaults
// (internal/natsapi, IMAS_SPROUT_ACTION_*, IMAS_SELF_UPDATE_CONCURRENCY),
// and refuses instead of queueing when one is full (farmer_busy). Such a
// refusal ran nothing: dispatchItem puts the item back to queued, and a
// rollout wave retries it after a short backoff (farmerBusyRetries).
//
// What this does not stop: several tenants together can still fill the
// cmd.run/cook pool (pool size / tenant cap of them, 8 by default); the
// per-tenant rate limit on POST .../sprouts/actions bounds how fast. A
// rollout is unaffected either way.

import (
	"sync"
	"sync/atomic"

	"github.com/yogzblr/imas/internal/controlplane"
)

// Defaults and bounds for the dispatch settings in OutboxSweeperSettings.
const (
	defaultActionDispatchConcurrency       = 64
	defaultSelfUpdateDispatchConcurrency   = 16
	defaultActionDispatchTenantConcurrency = 8
	maxDispatchConcurrency                 = 1024
)

// dispatchLimiter admits dispatches, blocking until both the action's
// pool and its tenant's cap in that pool have room. Tenants are keyed by
// tenant_id alone: the cap is per tenant, not per sprout.
type dispatchLimiter struct {
	mu        sync.Mutex
	cond      *sync.Cond
	tenantCap int
	pools     map[bool]*dispatchPool // keyed by "is self_update"
}

type dispatchPool struct {
	size, used int
	byTenant   map[string]int
}

func newDispatchLimiter(general, selfUpdate, tenantCap int) *dispatchLimiter {
	l := &dispatchLimiter{tenantCap: tenantCap, pools: map[bool]*dispatchPool{
		false: {size: general, byTenant: map[string]int{}},
		true:  {size: selfUpdate, byTenant: map[string]int{}},
	}}
	l.cond = sync.NewCond(&l.mu)
	return l
}

// acquire waits for a slot for one item of actionType from tenantID and
// returns its release func, which is safe to call more than once.
func (l *dispatchLimiter) acquire(tenantID, actionType string) func() {
	p := l.pools[actionType == controlplane.ActionSelfUpdate]
	l.mu.Lock()
	for p.byTenant[tenantID] >= l.tenantCap || p.used >= p.size {
		l.cond.Wait()
	}
	p.used++
	p.byTenant[tenantID]++
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			p.used--
			if p.byTenant[tenantID]--; p.byTenant[tenantID] <= 0 {
				delete(p.byTenant, tenantID)
			}
			l.mu.Unlock()
			l.cond.Broadcast()
		})
	}
}

// inUse reports the slots tenantID and everyone hold in actionType's
// pool, for tests and logs.
func (l *dispatchLimiter) inUse(tenantID, actionType string) (tenant, total int) {
	p := l.pools[actionType == controlplane.ActionSelfUpdate]
	l.mu.Lock()
	defer l.mu.Unlock()
	return p.byTenant[tenantID], p.used
}

// dispatchLimits is the limiter in use. setDispatchLimits replaces it; a
// dispatch releases its slot to the limiter it took it from.
var dispatchLimits atomic.Pointer[dispatchLimiter]

func init() {
	dispatchLimits.Store(newDispatchLimiter(defaultActionDispatchConcurrency,
		defaultSelfUpdateDispatchConcurrency, defaultActionDispatchTenantConcurrency))
}

// setDispatchLimits installs a limiter with these sizes. A value outside
// [1, maxDispatchConcurrency] (zero: not set) takes its default.
func setDispatchLimits(general, selfUpdate, tenantCap int) {
	pick := func(v, def int) int {
		if v < 1 || v > maxDispatchConcurrency {
			return def
		}
		return v
	}
	dispatchLimits.Store(newDispatchLimiter(
		pick(general, defaultActionDispatchConcurrency),
		pick(selfUpdate, defaultSelfUpdateDispatchConcurrency),
		pick(tenantCap, defaultActionDispatchTenantConcurrency)))
}
