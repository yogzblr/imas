package harness

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// Default waits. A batch reply can take 45 seconds plus the command's own
// timeout before saasapi gives up on it (docs/api/saasapi.md), so the
// batch wait is longer than that.
const (
	DefaultBatchTimeout   = 4 * time.Minute
	DefaultCookTimeout    = 6 * time.Minute
	DefaultConnectTimeout = 10 * time.Minute
	DefaultTenantTimeout  = 5 * time.Minute
)

// Fleet ties the harness together for one run.
type Fleet struct {
	Env    *Env
	API    *Client
	Tokens *Tokens
	VM     *VMCtl
	Enroll *Enroller
	// HTTP11 is an HTTP/1.1-only client with the run's CA, for raw
	// requests to Envoy such as a websocket upgrade.
	HTTP11 *http.Client
	// BindExec, when set, replaces running bind-tenant.sh: it gets the
	// script's arguments and returns its stdout and stderr. For tests.
	BindExec func(ctx context.Context, args []string) (stdout, stderr []byte, err error)

	prepareOnce sync.Once
	prepareErr  error
	mu          sync.Mutex
	sprouts     []Sprout
	notReady    map[string]error
}

// NewFleet builds a Fleet from a loaded Env.
func NewFleet(env *Env) (*Fleet, error) {
	hc := NewHTTPClient(env.CAPool, 60*time.Second)
	tok, err := NewTokens(env.Keycloak, hc)
	if err != nil {
		return nil, err
	}
	sprouts := make([]Sprout, len(env.Sprouts))
	copy(sprouts, env.Sprouts)
	return &Fleet{
		Env:      env,
		API:      NewClient(env.SaaSAPIURL, env.InternalAuth, hc),
		Tokens:   tok,
		VM:       NewVMCtl(env.VMCtlPath, env.UATFile),
		Enroll:   &Enroller{EnvoyURL: env.EnvoyURL, HTTP: hc},
		HTTP11:   NewHTTP11Client(env.CAPool, 60*time.Second),
		sprouts:  sprouts,
		notReady: map[string]error{},
	}, nil
}

// TenantID is the saasapi ID of tenant 1 or 2.
func (f *Fleet) TenantID(n int) string { return f.Env.TenantID(n) }

// Admin returns tenant n's admin token.
func (f *Fleet) Admin(ctx context.Context, n int) (string, error) {
	return f.Tokens.Tenant(ctx, n, RoleAdmin)
}

// Filter selects sprouts.
type Filter func(Sprout) bool

// InTenant selects a tenant's sprouts.
func InTenant(n int) Filter { return func(s Sprout) bool { return s.Tenant == n } }

// WithOS selects sprouts of an OS.
func WithOS(os string) Filter { return func(s Sprout) bool { return s.OS == os } }

// Linux selects the Linux sprouts.
func Linux() Filter { return func(s Sprout) bool { return !s.IsWindows() } }

// Sprouts returns the run's sprouts matching every filter, with their
// sprout IDs once Prepare has resolved them.
func (f *Fleet) Sprouts(filters ...Filter) []Sprout {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Sprout
next:
	for _, s := range f.sprouts {
		for _, fl := range filters {
			if !fl(s) {
				continue next
			}
		}
		out = append(out, s)
	}
	return out
}

// Assets returns the asset IDs of sprouts.
func Assets(sprouts []Sprout) []string {
	out := make([]string, len(sprouts))
	for i, s := range sprouts {
		out[i] = s.AssetID
	}
	return out
}

// Prepare resolves every sprout's ID and links its asset ID, once per
// Fleet. A sprout that can't be prepared is recorded (see Ready) and the
// others go on; the error is set only when nothing could be done.
func (f *Fleet) Prepare(ctx context.Context) error {
	f.prepareOnce.Do(func() { f.prepareErr = f.prepare(ctx) })
	return f.prepareErr
}

func (f *Fleet) prepare(ctx context.Context) error {
	var wg sync.WaitGroup
	f.mu.Lock()
	sprouts := make([]Sprout, len(f.sprouts))
	copy(sprouts, f.sprouts)
	f.mu.Unlock()
	for i := range sprouts {
		if sprouts[i].SproutID != "" {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := f.readSproutID(ctx, sprouts[i])
			f.mu.Lock()
			defer f.mu.Unlock()
			if err != nil {
				f.notReady[sprouts[i].VM] = fmt.Errorf("resolving its sprout ID: %w", err)
				return
			}
			f.sprouts[i].SproutID = id
		}(i)
	}
	wg.Wait()
	for _, n := range f.Env.Tenants() {
		if err := f.EnsureLinked(ctx, n); err != nil {
			return err
		}
	}
	return nil
}

// readSproutID reads the sprout_id claim of the sprout's gateway JWT on
// the host: the ID farmer issued it.
func (f *Fleet) readSproutID(ctx context.Context, sp Sprout) (string, error) {
	res, err := f.OnHost(ctx, sp, GatewayClaims())
	if err != nil {
		return "", err
	}
	seg, _ := res.Value("GW_PAYLOAD")
	if seg == "" {
		return "", fmt.Errorf("no gateway JWT on the host (is the sprout enrolled?): %s", tail([]byte(res.Output), 300))
	}
	claims, err := DecodeSegment(seg)
	if err != nil {
		return "", err
	}
	id := ClaimString(claims, "sprout_id")
	if id == "" {
		return "", errors.New("the gateway JWT has no sprout_id claim")
	}
	return id, nil
}

// HostClaims returns the claims of the sprout's gateway JWT, read on the
// host.
func (f *Fleet) HostClaims(ctx context.Context, sp Sprout) (map[string]any, error) {
	res, err := f.OnHost(ctx, sp, GatewayClaims())
	if err != nil {
		return nil, err
	}
	seg, _ := res.Value("GW_PAYLOAD")
	if seg == "" {
		return nil, fmt.Errorf("no gateway JWT on the host: %s", tail([]byte(res.Output), 300))
	}
	return DecodeSegment(seg)
}

// EnsureLinked links every prepared sprout of tenant n to its asset ID,
// skipping the ones a lookup already resolves to the right sprout.
func (f *Fleet) EnsureLinked(ctx context.Context, n int) error {
	tok, err := f.Admin(ctx, n)
	if err != nil {
		return fmt.Errorf("tenant %d token: %w", n, err)
	}
	tid := f.TenantID(n)
	var todo []Sprout
	for _, s := range f.Sprouts(InTenant(n)) {
		if s.SproutID != "" {
			todo = append(todo, s)
		}
	}
	if len(todo) == 0 {
		return nil
	}
	lk, r, err := f.API.LookupAssets(ctx, tok, tid, Assets(todo))
	if err != nil {
		return err
	}
	if r.Status != http.StatusOK {
		return fmt.Errorf("tenant %d asset lookup: %s", n, r)
	}
	for _, s := range todo {
		if res, ok := lk.Find(s.AssetID); ok && res.SproutID == s.SproutID {
			continue
		}
		r, err := f.API.LinkAsset(ctx, tok, tid, s.SproutID, s.AssetID)
		if err == nil && r.Status != http.StatusCreated && r.Status != http.StatusOK {
			err = fmt.Errorf("linking asset %s to sprout %s: %s", s.AssetID, s.SproutID, r)
		}
		if err != nil {
			f.mu.Lock()
			f.notReady[s.VM] = err
			f.mu.Unlock()
		}
	}
	return nil
}

// Ready returns why a sprout couldn't be prepared, or nil.
func (f *Fleet) Ready(sp Sprout) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.notReady[sp.VM]; err != nil {
		return err
	}
	for _, s := range f.sprouts {
		if s.VM == sp.VM && s.SproutID == "" {
			return errors.New("its sprout ID is not known (Prepare was not called, or failed)")
		}
	}
	return nil
}

// EachTenant runs fn in a subtest named t<n> for each tenant that has
// sprouts, in parallel.
func (f *Fleet) EachTenant(t *testing.T, sc *Scenario, fn func(t *testing.T, sc *Scenario, tenant int)) {
	t.Helper()
	for _, n := range f.Env.Tenants() {
		t.Run(fmt.Sprintf("t%d", n), func(t *testing.T) {
			t.Parallel()
			fn(t, sc.ForTenant(t, n), n)
		})
	}
}

// EachSprout runs fn in a subtest per sprout, named by Sprout.Name, in
// parallel. A sprout Prepare couldn't resolve fails its subtest.
func (f *Fleet) EachSprout(t *testing.T, sc *Scenario, sprouts []Sprout, fn func(t *testing.T, sc *Scenario, sp Sprout)) {
	t.Helper()
	if len(sprouts) == 0 {
		sc.Fatalf("no sprouts match: uat.json has none of the kind this scenario needs")
	}
	for _, sp := range sprouts {
		t.Run(sp.Name(), func(t *testing.T) {
			t.Parallel()
			ssc := sc.ForSprout(t, sp)
			if err := f.Ready(sp); err != nil {
				ssc.Fatalf("sprout not ready: %v", err)
			}
			fn(t, ssc, sp)
		})
	}
}

// Do posts an action for the sprouts of tenant n (their asset IDs, in
// order), waiting out rate limits, and waits for the batch to complete.
func (f *Fleet) Do(ctx context.Context, n int, sprouts []Sprout, act Action) (*Batch, error) {
	timeout := DefaultBatchTimeout
	if act.Type == "cook" {
		timeout = DefaultCookTimeout
	}
	return f.DoAssets(ctx, n, Assets(sprouts), act, timeout)
}

// DoAssets is Do for raw asset IDs and a timeout of the caller's.
func (f *Fleet) DoAssets(ctx context.Context, n int, assets []string, act Action, timeout time.Duration) (*Batch, error) {
	tok, err := f.Admin(ctx, n)
	if err != nil {
		return nil, err
	}
	id, err := f.API.StartBatch(ctx, tok, f.TenantID(n), assets, act)
	if err != nil {
		return nil, fmt.Errorf("posting the %s batch: %w", act.Type, err)
	}
	return f.API.WaitBatch(ctx, tok, f.TenantID(n), id, timeout)
}

// Cook cooks a recipe on the sprouts of tenant n and waits for it.
func (f *Fleet) Cook(ctx context.Context, n int, sprouts []Sprout, recipe string, test bool) (*Batch, error) {
	return f.Do(ctx, n, sprouts, CookAction(recipe, test))
}

// OnHost runs a host script on a sprout's VM through vmctl.sh, outside the
// platform.
func (f *Fleet) OnHost(ctx context.Context, sp Sprout, h HostScript) (*RunResult, error) {
	return f.VM.Run(ctx, sp.VM, sp.Family(), h.For(sp.Family()))
}

// File returns the state of a file on a sprout's host.
func (f *Fleet) File(ctx context.Context, sp Sprout, path string) (FileInfo, error) {
	res, err := f.OnHost(ctx, sp, FileState(sp, path))
	if err != nil {
		return FileInfo{}, err
	}
	return ParseFileState(res)
}

// WaitConnected waits until saasapi reports every sprout connected (its
// tenant's lookup, from farmer's heartbeats), or until timeout.
func (f *Fleet) WaitConnected(ctx context.Context, sprouts []Sprout, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var missing []string
		var lastErr error
		byTenant := map[int][]Sprout{}
		for _, s := range sprouts {
			byTenant[s.Tenant] = append(byTenant[s.Tenant], s)
		}
		for n, ss := range byTenant {
			tok, err := f.Admin(ctx, n)
			if err != nil {
				return err
			}
			lk, r, err := f.API.LookupAssets(ctx, tok, f.TenantID(n), Assets(ss))
			if err == nil && r.Status != http.StatusOK {
				err = fmt.Errorf("lookup: %s", r)
			}
			if err != nil {
				lastErr = err
				for _, s := range ss {
					missing = append(missing, s.VM)
				}
				continue
			}
			for _, s := range ss {
				if res, ok := lk.Find(s.AssetID); !ok || !res.Connected {
					missing = append(missing, s.VM)
				}
			}
		}
		if len(missing) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			msg := fmt.Sprintf("not connected after %s: %s", timeout, strings.Join(missing, ", "))
			if lastErr != nil {
				msg += fmt.Sprintf(" (last error: %v)", lastErr)
			}
			return errors.New(msg)
		}
		if err := sleep(ctx, 5*time.Second); err != nil {
			return err
		}
	}
}

// WaitRuns retries a harmless cmd.run on the sprouts until each one
// succeeds, or until timeout: the proof that a sprout is back after a
// restart, stronger than the heartbeat.
func (f *Fleet) WaitRuns(ctx context.Context, sprouts []Sprout, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	pending := append([]Sprout(nil), sprouts...)
	for {
		var still []Sprout
		var detail []string
		byTenant := map[int][]Sprout{}
		for _, s := range pending {
			byTenant[s.Tenant] = append(byTenant[s.Tenant], s)
		}
		for n, ss := range byTenant {
			for _, fam := range []string{FamilyLinux, FamilyWindows} {
				var group []Sprout
				for _, s := range ss {
					if s.Family() == fam {
						group = append(group, s)
					}
				}
				if len(group) == 0 {
					continue
				}
				b, err := f.Do(ctx, n, group, CmdRunAction(TrueCmd(group[0])))
				for _, s := range group {
					it, ok := b.For(s)
					if err != nil || !ok || it.Status != ItemSucceeded {
						still = append(still, s)
						if ok {
							detail = append(detail, s.VM+": "+it.String())
						} else if err != nil {
							detail = append(detail, s.VM+": "+err.Error())
						}
					}
				}
			}
		}
		if len(still) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no successful cmd.run within %s: %s", timeout, strings.Join(detail, "; "))
		}
		pending = still
		if err := sleep(ctx, 10*time.Second); err != nil {
			return err
		}
	}
}

// DefaultRestartCommands restart farmer (on core), and the bus and Envoy
// (on the DMZ), on single-node k0s hubs, by the component labels the
// charts set (deploy/helm/*/templates/_helpers.tpl). harness.json's
// restart map overrides them, for example on the local rig.
func (f *Fleet) DefaultRestartCommands() map[string]RestartCommand {
	core, dmz := f.Env.UAT.Core.Name, f.Env.UAT.DMZ.Name
	if core == "" {
		core = "uat-core"
	}
	if dmz == "" {
		dmz = "uat-dmz"
	}
	return map[string]RestartCommand{
		"farmer":    {VM: core, Command: restartScript("deployment", "farmer")},
		"farmerbus": {VM: dmz, Command: restartScript("statefulset", "bus")},
		"envoy":     {VM: dmz, Command: restartScript("deployment", "envoy")},
	}
}

// RestartCommand returns the command for a workload: harness.json's, or
// the default.
func (f *Fleet) RestartCommand(name string) (RestartCommand, error) {
	if c, ok := f.Env.Settings.Restart[name]; ok && c.Command != "" {
		if c.VM == "" {
			c.VM = f.DefaultRestartCommands()[name].VM
		}
		return c, nil
	}
	c, ok := f.DefaultRestartCommands()[name]
	if !ok {
		return RestartCommand{}, fmt.Errorf("no restart command for %q", name)
	}
	return c, nil
}

// RestartWorkload runs a restart command through vmctl.sh and fails
// unless it exits 0.
func (f *Fleet) RestartWorkload(ctx context.Context, name string) error {
	c, err := f.RestartCommand(name)
	if err != nil {
		return err
	}
	res, err := f.VM.Run(ctx, c.VM, FamilyLinux, c.Command)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("restarting %s on %s exited %d: %s", name, c.VM, res.ExitCode, tail([]byte(res.Output), 800))
	}
	return nil
}

func restartScript(kind, component string) string {
	return fmt.Sprintf(`k=kubectl
command -v k0s >/dev/null 2>&1 && k="k0s kubectl"
list=$($k get %[1]s -A -l app.kubernetes.io/component=%[2]s -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{" "}{end}')
if [ -z "$list" ]; then echo "no %[1]s labelled app.kubernetes.io/component=%[2]s"; exit 3; fi
for item in $list; do
  ns=${item%%%%/*}; name=${item#*/}
  $k -n "$ns" rollout restart %[1]s/"$name" || exit 4
done
for item in $list; do
  ns=${item%%%%/*}; name=${item#*/}
  $k -n "$ns" rollout status %[1]s/"$name" --timeout=600s || exit 5
done`, kind, component)
}
