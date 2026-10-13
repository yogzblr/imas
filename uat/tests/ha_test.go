//go:build uat

package uattests

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

// The ha tier (docs/briefs/H-azure-next-runs.md, H5; P24 item 6, P23):
// HA1 to HA6 take pods, nodes and events away from the HA run's hubs (3
// core and 3 DMZ k0s nodes) while loops make an API call every second,
// enrol a sprout every 10 s and run cmd.run every 5 s, and check the
// owner's error windows (harness/loops.go). On the single-node run every
// scenario skips, saying so. uat/tests/README.md maps design tests T1 to
// T8 onto these and the other tiers.

// haReady returns the fleet with its sprouts prepared and the HA handle,
// skipping the scenario on single-node hubs.
func haReady(t *testing.T, sc *harness.Scenario) (*harness.Fleet, *harness.HA) {
	t.Helper()
	h, err := fleet.HA()
	if errors.Is(err, harness.ErrNotHA) {
		sc.Skipf("%v", err)
	}
	sc.NoErr(err, "reaching the hubs' clusters")
	return ready(t, sc), h
}

// traffic starts the loops with a fresh marker file and returns them, the
// enroller and what CheckMarkers needs.
func traffic(t *testing.T, sc *harness.Scenario, f *harness.Fleet, key harness.EnrollmentKey, id string, recipes bool) (*harness.Running, *harness.FullEnroller, string, *harness.Ledger) {
	t.Helper()
	fe := harness.NewFullEnroller(f.Env.EnvoyURL, f.API.HTTP)
	marker := "imas-uat-" + strings.ToLower(id) + "-" + harness.Nonce(8)
	plan, ledger := f.TrafficPlan(harness.Traffic{
		Cadence: harness.DefaultLoopPlan(), JoinToken: key.RegistrationKey, Enroller: fe, Marker: marker, Recipes: recipes,
	})
	sc.Step("start the loops (API every 1 s, enrolment every 10 s, cmd.run every 5 s%s)", map[bool]string{true: ", a recipe every 15 s"}[recipes])
	run := harness.StartLoops(ctxFor(t, 2*time.Hour), plan)
	t.Cleanup(func() { run.Stop() })
	return run, fe, marker, ledger
}

// settle lets the loops run for d, failing the test if its context ends.
func settle(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case <-time.After(d):
	case <-ctxFor(t, d+time.Minute).Done():
	}
}

// checkWindow logs the record's timings and fails the test for each
// breach of the window.
func checkWindow(sc *harness.Scenario, rec *harness.Record, w harness.Window) {
	sc.Logf("timings: %s", rec.Summary())
	for _, v := range rec.Violations(w) {
		sc.Errorf("%s", v)
	}
}

// checkIdentities checks the enrolments made under the loops: each one a
// distinct sprout, NKey, box key, User JWT and gateway JWT, and enrolled
// again it gets the same sprout and the same User JWT (one JWT per sprout
// across the farmer replicas, design T6; the box key on record is the
// one it proved).
func checkIdentities(t *testing.T, sc *harness.Scenario, fe *harness.FullEnroller, list []*harness.Enrolment) {
	t.Helper()
	if len(list) == 0 {
		sc.Errorf("%v", harness.ErrNoEnrolments)
		return
	}
	sc.Step("check the %d enrolments: no duplicate sprout, NKey, box key or JWT", len(list))
	for _, d := range harness.Duplicates(list) {
		sc.Errorf("duplicate: %s", d)
	}
	sc.Step("enrol each of them again: the same sprout and the same User JWT")
	for _, e := range fe.ReplayAll(ctxFor(t, 30*time.Minute), list) {
		sc.Errorf("%s", e)
	}
}

// checkMarkers checks no cmd.run ran twice (design T8).
func checkMarkers(t *testing.T, sc *harness.Scenario, f *harness.Fleet, marker string, ledger *harness.Ledger) {
	t.Helper()
	sc.Step("read the marker file on every sprout: every cmd.run ran once")
	for _, v := range f.CheckMarkers(ctxFor(t, 20*time.Minute), marker, ledger) {
		sc.Errorf("%s", v)
	}
}

// killTarget is one pod HA1 deletes.
type killTarget struct {
	name, ns, selector string
	kube               *harness.Kube
	pod                string // a bus pod by name; empty: the first pod
}

func TestHAHA1_PodKill(t *testing.T) {
	sc := harness.Begin(t, "HA1")
	f, h := haReady(t, sc)
	key := mintKey(t, sc, 1, 12, 5000)
	targets := []killTarget{
		{name: "farmer", ns: harness.CoreNamespace, selector: harness.Selector("farmer"), kube: h.Core},
		{name: "saasapi", ns: harness.CoreNamespace, selector: harness.Selector("saasapi"), kube: h.Core},
		{name: "envoy", ns: harness.DMZNamespace, selector: harness.Selector("envoy"), kube: h.DMZ},
	}
	bus, err := h.BusPods(ctxFor(t, time.Minute))
	sc.NoErr(err, "listing the bus pods")
	for _, p := range bus {
		targets = append(targets, killTarget{name: p.Name, ns: harness.DMZNamespace, selector: harness.Selector("bus"), kube: h.DMZ, pod: p.Name})
	}
	var all []*harness.Enrolment
	var fe *harness.FullEnroller
	for _, tg := range targets {
		t.Run(tg.name, func(t *testing.T) {
			ssc := harness.Begin(t, "HA1")
			ctx := ctxFor(t, 30*time.Minute)
			pods, err := tg.kube.Pods(ctx, tg.ns, tg.selector)
			ssc.NoErr(err, "listing %s", tg.name)
			live := harness.Live(pods)
			if len(live) < 2 {
				ssc.Fatalf("%s runs %d pods; the HA run has 3", tg.name, len(live))
			}
			victim := live[0]
			for _, p := range live {
				if p.Name == tg.pod {
					victim = p
				}
			}
			var expected harness.LoaderStatus
			if tg.pod != "" {
				for _, p := range live {
					if p.Name != victim.Name {
						expected, err = h.LoaderStatusOf(ctx, p)
						ssc.NoErr(err, "the loader status of %s", p.Name)
						break
					}
				}
				ssc.Logf("the other loaders hold %d of %d accounts", expected.Applied, expected.Target)
			}
			run, enroller, marker, ledger := traffic(t, ssc, f, key, "HA1", false)
			fe = enroller
			settle(t, 20*time.Second)
			ssc.Step("delete pod %s/%s", tg.ns, victim.Name)
			run.Mark("deleted " + victim.Name)
			ssc.NoErr(tg.kube.DeletePod(ctx, tg.ns, victim.Name), "deleting %s", victim.Name)
			var watch *loaderWatch
			if tg.pod != "" {
				watch = watchLoader(ctx, h, victim)
			}
			ssc.Step("wait for %d Ready %s pods again", len(live), tg.name)
			_, err = harness.WaitPodsReady(ctx, tg.kube, tg.ns, tg.selector, len(live), []string{victim.UID}, 10*time.Minute)
			ssc.NoErr(err, "the replacement")
			run.Mark(tg.name + " Ready again")
			if watch != nil {
				ssc.Step("the restarted bus node's loader was ready only with every account")
				for _, v := range watch.stop(ctx, expected) {
					ssc.Errorf("%s", v)
				}
			}
			ssc.Step("keep the loops running for 45 s")
			settle(t, 45*time.Second)
			rec := run.Stop()
			all = append(all, rec.Enrolments...)
			checkWindow(ssc, rec, harness.PodKillWindow)
			checkMarkers(t, ssc, f, marker, ledger)
		})
	}
	if fe != nil {
		checkIdentities(t, sc, fe, all)
	}
}

// loaderWatch follows a restarted bus pod's loader through its start.
type loaderWatch struct {
	mu     sync.Mutex
	issues []string
	seen   int
	done   chan struct{}
	cancel context.CancelFunc
	last   harness.LoaderStatus
	h      *harness.HA
	name   string
}

// watchLoader polls the loader of the pod that replaces old (same name, new
// UID) every half second, through a port-forward, from the moment its
// containers run until stop: whenever it says ready, or the pod is Ready,
// it must hold every account it targets.
func watchLoader(ctx context.Context, h *harness.HA, old harness.Pod) *loaderWatch {
	wctx, cancel := context.WithCancel(ctx)
	w := &loaderWatch{done: make(chan struct{}), cancel: cancel, h: h, name: old.Name}
	go func() {
		defer close(w.done)
		var fwd *harness.LoaderForward
		defer func() {
			if fwd != nil {
				fwd.Close()
			}
		}()
		for wctx.Err() == nil {
			time.Sleep(500 * time.Millisecond)
			p, ok, err := h.DMZ.GetPod(wctx, harness.DMZNamespace, old.Name)
			if err != nil || !ok || p.UID == old.UID || p.Phase != "Running" {
				continue
			}
			if fwd == nil {
				if fwd, err = h.ForwardLoader(wctx, p); err != nil {
					fwd = nil
					continue
				}
			}
			st, err := fwd.Status(wctx)
			if err != nil {
				continue
			}
			w.mu.Lock()
			w.seen++
			w.last = st
			if (st.Ready || p.Containers[harness.LoaderContainer]) && (st.Applied < st.Target || st.Target == 0) {
				w.issues = append(w.issues, fmt.Sprintf("the loader of %s said ready (pod Ready %v, loader ready %v) holding %d of %d accounts",
					p.Name, p.Ready, st.Ready, st.Applied, st.Target))
			}
			w.mu.Unlock()
		}
	}()
	return w
}

// stop ends the watch and checks the loader's last word against the other
// loaders' (expected).
func (w *loaderWatch) stop(ctx context.Context, expected harness.LoaderStatus) []string {
	w.cancel()
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	out := append([]string(nil), w.issues...)
	if w.seen == 0 {
		out = append(out, "the restarted loader's /status was never read")
		return out
	}
	if !w.last.Ready || w.last.Applied != w.last.Target || w.last.Target < expected.Target {
		out = append(out, fmt.Sprintf("the restarted loader ended %q with %d of %d accounts; the others hold %d",
			w.last.State, w.last.Applied, w.last.Target, expected.Target))
	}
	return out
}

func TestHAHA2_NodeStop(t *testing.T) {
	sc := harness.Begin(t, "HA2")
	f, h := haReady(t, sc)
	key := mintKey(t, sc, 1, 12, 5000)
	for _, hub := range []string{"core", "dmz"} {
		t.Run(hub, func(t *testing.T) {
			ssc := harness.Begin(t, "HA2")
			ctx := ctxFor(t, 90*time.Minute)
			k, namespaces := h.Core, []string{harness.CoreNamespace, harness.UATNamespace}
			pick := h.CoreStopNode
			if hub == "dmz" {
				k, namespaces, pick = h.DMZ, []string{harness.DMZNamespace}, h.DMZStopNode
			}
			ssc.Step("choose the %s node to stop", hub)
			vm, node, err := pick(ctx)
			ssc.NoErr(err, "choosing the node")
			ssc.Logf("stopping VM %s (node %s)", vm.Name, node)
			run, fe, marker, ledger := traffic(t, ssc, f, key, "HA2", true)
			settle(t, 20*time.Second)
			stopped := false
			t.Cleanup(func() {
				if stopped {
					if err := f.VM.StartVM(context.Background(), vm.Name); err != nil {
						t.Logf("starting %s again after the test: %v", vm.Name, err)
					}
				}
			})
			ssc.Step("stop VM %s (vmctl.sh stop-vm)", vm.Name)
			run.Mark("stopping " + vm.Name)
			stopped = true
			ssc.NoErr(f.VM.StopVM(ctx, vm.Name), "stopping %s", vm.Name)
			run.Mark(vm.Name + " stopped")
			if hub == "core" {
				ssc.Step("PXC, OpenBao and Valkey serve with two replicas")
				var rep harness.StatefulReport
				err := retryFor(ctx, 4*time.Minute, 10*time.Second, func() error {
					var err error
					rep, err = h.CheckStateful(ctx, node, 2)
					return err
				})
				if err != nil {
					ssc.Errorf("with %s stopped: %v", vm.Name, err)
				} else {
					ssc.Logf("with %s stopped: PXC %s; OpenBao %s; Valkey %s", vm.Name, rep.PXC, rep.OpenBao, rep.Valkey)
				}
			}
			ssc.Step("keep the loops running with the node stopped")
			settle(t, 150*time.Second)
			rec := run.Stop()
			checkWindow(ssc, rec, harness.NodeStopWindow)
			ssc.Step("start VM %s (vmctl.sh start-vm)", vm.Name)
			startedAt := time.Now()
			ssc.NoErr(f.VM.StartVM(ctx, vm.Name), "starting %s", vm.Name)
			stopped = false
			ssc.Step("node %s and its pods Ready within 10 minutes of the start", node)
			if err := h.WaitNodeBack(ctx, k, node, namespaces, 10*time.Minute-time.Since(startedAt)); err != nil {
				ssc.Errorf("%v", err)
			} else {
				ssc.Logf("node %s and its pods Ready %s after the start", node, time.Since(startedAt).Round(time.Second))
			}
			if hub == "core" {
				ssc.Step("PXC, OpenBao and Valkey back at three replicas")
				if err := retryFor(ctx, 5*time.Minute, 10*time.Second, func() error {
					_, err := h.CheckStateful(ctx, "", 3)
					return err
				}); err != nil {
					ssc.Errorf("after the start: %v", err)
				}
			}
			ssc.Step("no data lost: the %d recipes made during the stop", len(rec.Recipes))
			if len(rec.Recipes) == 0 {
				ssc.Errorf("no recipe was created during the stop, so nothing shows it survived")
			}
			for _, v := range f.CheckRecipes(ctx, rec.Recipes) {
				ssc.Errorf("%s", v)
			}
			checkIdentities(t, ssc, fe, rec.Enrolments)
			checkMarkers(t, ssc, f, marker, ledger)
			ssc.Step("every sprout runs a job again")
			ssc.NoErr(f.WaitRuns(ctx, f.Sprouts(), 10*time.Minute), "after the node came back")
		})
	}
}

// retryFor calls fn every every until it succeeds or for, returning its
// last error.
func retryFor(ctx context.Context, d, every time.Duration, fn func() error) error {
	deadline := time.Now().Add(d)
	for {
		err := fn()
		if err == nil || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(every):
		}
	}
}

// podUIDs lists the UIDs of a selector's live pods.
func podUIDs(t *testing.T, sc *harness.Scenario, k *harness.Kube, ns, selector string) map[string]bool {
	t.Helper()
	pods, err := k.Pods(ctxFor(t, time.Minute), ns, selector)
	sc.NoErr(err, "listing %s", selector)
	out := map[string]bool{}
	for _, p := range harness.Live(pods) {
		out[p.UID] = true
	}
	return out
}

func TestHAHA3_RollingRestart(t *testing.T) {
	sc := harness.Begin(t, "HA3")
	f, h := haReady(t, sc)
	ctx := ctxFor(t, 90*time.Minute)
	key := mintKey(t, sc, 1, 12, 5000)
	before := map[string]map[string]bool{
		"farmer":  podUIDs(t, sc, h.Core, harness.CoreNamespace, harness.Selector("farmer")),
		"saasapi": podUIDs(t, sc, h.Core, harness.CoreNamespace, harness.Selector("saasapi")),
		"bus":     podUIDs(t, sc, h.DMZ, harness.DMZNamespace, harness.Selector("bus")),
	}
	run, fe, marker, ledger := traffic(t, sc, f, key, "HA3", false)
	settle(t, 20*time.Second)
	stamp := harness.Nonce(10)
	sc.Step("helm upgrade the core release: farmer and saasapi get pod annotation %s=%s", harness.UpgradeAnnotation, stamp)
	run.Mark("core upgrade")
	sc.NoErr(h.HelmUpgrade(ctx, "core",
		"farmer.podAnnotations."+harness.UpgradeAnnotation+"="+stamp,
		"saasapi.podAnnotations."+harness.UpgradeAnnotation+"="+stamp), "upgrading the core release")
	sc.Step("helm upgrade the DMZ release: the bus gets the annotation")
	run.Mark("DMZ upgrade")
	sc.NoErr(h.HelmUpgrade(ctx, "dmz", "bus.podAnnotations."+harness.UpgradeAnnotation+"="+stamp), "upgrading the DMZ release")
	run.Mark("upgrades done")
	settle(t, 45*time.Second)
	rec := run.Stop()
	checkWindow(sc, rec, harness.RollingWindow)
	sc.Step("every farmer, saasapi and bus pod was replaced")
	for name, k := range map[string]*harness.Kube{"farmer": h.Core, "saasapi": h.Core, "bus": h.DMZ} {
		ns := harness.CoreNamespace
		if name == "bus" {
			ns = harness.DMZNamespace
		}
		for uid := range podUIDs(t, sc, k, ns, harness.Selector(name)) {
			if before[name][uid] {
				sc.Errorf("a %s pod was not restarted by the upgrade", name)
			}
		}
	}
	sc.Step("the sprouts stayed enrolled: each resolves to the same sprout, accepted")
	for _, n := range f.Env.Tenants() {
		tok := token(t, sc, n, harness.RoleAdmin)
		ss := f.Sprouts(harness.InTenant(n))
		lk, r, err := f.API.LookupAssets(ctx, tok, f.TenantID(n), harness.Assets(ss))
		sc.Expect(r, err, 200, "", "lookup in tenant %d", n)
		for _, sp := range ss {
			res, ok := lk.Find(sp.AssetID)
			if !ok || res.SproutID != sp.SproutID || res.KeyState != "accepted" {
				sc.Errorf("sprout %s: %+v (found %v), want sprout %s accepted", sp.VM, res, ok, sp.SproutID)
			}
		}
	}
	sc.NoErr(f.WaitRuns(ctx, f.Sprouts(), 10*time.Minute), "every sprout runs a job after the upgrades")
	checkIdentities(t, sc, fe, rec.Enrolments)
	checkMarkers(t, sc, f, marker, ledger)
	sc.Step("uat/hub/core/check.sh after the upgrade (design T4: the bootstrap Job stayed idempotent)")
	out, err := h.RunCoreCheck(ctx)
	if err != nil {
		var fails []string
		for _, l := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(l, "FAIL") {
				fails = append(fails, l)
			}
		}
		sc.Errorf("the core check failed after the upgrade (%v): %s", err, strings.Join(fails, "; "))
	}
}

func TestHAHA4_EmptyBusNode(t *testing.T) {
	sc := harness.Begin(t, "HA4")
	f, h := haReady(t, sc)
	ctx := ctxFor(t, 60*time.Minute)
	key := mintKey(t, sc, 1, 2, 10)
	fe := harness.NewFullEnroller(f.Env.EnvoyURL, f.API.HTTP)
	sc.Step("enrol a sprout while farmer runs")
	e, err := harness.NewEnrolment("uat-ha4-"+harness.Nonce(8), key.RegistrationKey)
	sc.NoErr(err, "keys")
	sc.NoErr(fe.Enrol(ctx, e), "enrolling")
	bus, err := h.BusPods(ctx)
	sc.NoErr(err, "listing the bus pods")
	if len(bus) < 2 {
		sc.Fatalf("the bus runs %d pods", len(bus))
	}
	victim, other := bus[len(bus)-1], bus[0]
	expected, err := h.LoaderStatusOf(ctx, other)
	sc.NoErr(err, "the loader status of %s", other.Name)
	want, _, err := h.Core.Replicas(ctx, harness.CoreNamespace, "deployment", harness.FarmerDeployment)
	sc.NoErr(err, "farmer's replicas")
	sc.Step("scale farmer to 0")
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		_ = h.Core.Scale(c, harness.CoreNamespace, "deployment", harness.FarmerDeployment, want)
	})
	sc.NoErr(h.Core.Scale(ctx, harness.CoreNamespace, "deployment", harness.FarmerDeployment, 0), "scaling farmer to 0")
	_, err = harness.WaitPodsReady(ctx, h.Core, harness.CoreNamespace, harness.Selector("farmer"), 0, nil, 5*time.Minute)
	sc.NoErr(err, "farmer's pods gone")
	sc.Step("delete bus pod %s and its emptyDir", victim.Name)
	sc.NoErr(h.DMZ.DeletePod(ctx, harness.DMZNamespace, victim.Name), "deleting %s", victim.Name)
	watch := watchLoader(ctx, h, victim)
	_, err = harness.WaitPodsReady(ctx, h.DMZ, harness.DMZNamespace, harness.Selector("bus"), len(bus), []string{victim.UID}, 10*time.Minute)
	sc.NoErr(err, "%s back with farmer at 0", victim.Name)
	sc.Step("its loader loaded every account from the object store alone")
	for _, v := range watch.stop(ctx, expected) {
		sc.Errorf("%s", v)
	}
	sc.Step("the node accepts the sprout enrolled before")
	pods, err := h.BusPods(ctx)
	sc.NoErr(err, "listing the bus pods")
	for _, p := range pods {
		if p.Name != victim.Name {
			continue
		}
		addr, stop, err := h.BusAddr(ctx, p)
		sc.NoErr(err, "forwarding to %s", p.Name)
		err = harness.BusConnect(ctx, addr, f.Env.CAPool, e)
		stop()
		if err != nil {
			sc.Errorf("%s with farmer at 0: %v", p.Name, err)
		}
	}
	sc.Step("scale farmer back to %d", want)
	sc.NoErr(h.Core.Scale(ctx, harness.CoreNamespace, "deployment", harness.FarmerDeployment, want), "scaling farmer back")
	_, err = harness.WaitPodsReady(ctx, h.Core, harness.CoreNamespace, harness.Selector("farmer"), want, nil, 10*time.Minute)
	sc.NoErr(err, "farmer back")
	sc.NoErr(f.WaitRuns(ctx, f.Sprouts(), 10*time.Minute), "every sprout runs a job again")
}

func TestHAHA5_LostEvent(t *testing.T) {
	sc := harness.Begin(t, "HA5")
	f, h := haReady(t, sc)
	ctx := ctxFor(t, 60*time.Minute)
	fe := harness.NewFullEnroller(f.Env.EnvoyURL, f.API.HTTP)
	bus, err := h.BusPods(ctx)
	sc.NoErr(err, "listing the bus pods")
	if len(bus) < 2 {
		sc.Fatalf("the bus runs %d pods", len(bus))
	}
	victim, others := bus[len(bus)-1], bus[:len(bus)-1]
	port, err := harness.AccountStorePort(victim)
	sc.NoErr(err, "the account store's port")
	interval, err := harness.ReconcileInterval(victim)
	sc.NoErr(err, "the loader's reconcile interval")

	sc.Step("a sprout in a scratch tenant (the one revoked below), accepted by every bus node")
	revokedTenant, revokedTok := scratchTenant(t, sc, "ha5-revoked", true)
	t.Cleanup(func() { offboard(t, revokedTenant, revokedTok) })
	revoked := enrolIn(t, sc, fe, revokedTenant, revokedTok)
	expectBus(t, sc, h, revoked, nil)

	sc.Step("keep %s's loader from the object store (NetworkPolicy, port %d)", victim.Name, port)
	unblock, err := h.BlockAccountStore(ctx, victim.Name, port)
	sc.NoErr(err, "blocking")
	blocked := true
	t.Cleanup(func() {
		if blocked {
			if err := unblock(context.Background()); err != nil {
				t.Logf("restoring the bus NetworkPolicy: %v", err)
			}
		}
	})
	before, err := h.LoaderStatusOf(ctx, victim)
	sc.NoErr(err, "the loader status of %s", victim.Name)
	sc.Step("restart the core edge proxy: every open connection to the object store is cut")
	sc.NoErr(h.Core.RolloutRestart(ctx, harness.UATNamespace, "deployment", harness.EdgeDeployment, 10*time.Minute), "restarting the edge")
	sc.Step("wait until %s's loader fails to reach the object store", victim.Name)
	var base harness.LoaderStatus
	err = retryFor(ctx, 3*interval+time.Minute, 5*time.Second, func() error {
		st, err := h.LoaderStatusOf(ctx, victim)
		if err != nil {
			return err
		}
		if st.S3Errors() <= before.S3Errors() {
			return fmt.Errorf("its object store errors are still %d", st.S3Errors())
		}
		base = st
		return nil
	})
	sc.NoErr(err, "the block did not take")

	sc.Step("create an account (a scratch tenant) and revoke the sprout (offboard its tenant)")
	newTenant, newTok := scratchTenant(t, sc, "ha5-new", true)
	t.Cleanup(func() { offboard(t, newTenant, newTok) })
	fresh := enrolIn(t, sc, fe, newTenant, newTok)
	r, err := f.API.DeleteTenant(ctx, revokedTok, revokedTenant)
	sc.Expect(r, err, 202, "", "offboarding tenant %s", revokedTenant)
	_, err = f.API.WaitTenantStatus(ctx, revokedTok, revokedTenant, harness.DefaultTenantTimeout, harness.TenantOffboarded)
	sc.NoErr(err, "waiting for offboarded")

	sc.Step("the other loaders take the change; %s's does not", victim.Name)
	var token string
	var target int
	err = retryFor(ctx, 2*time.Minute, 2*time.Second, func() error {
		token, target = "", 0
		for _, p := range others {
			st, err := h.LoaderStatusOf(ctx, p)
			if err != nil {
				return err
			}
			if st.LastIndexToken == base.LastIndexToken || (token != "" && st.LastIndexToken != token) || st.Applied != st.Target {
				return fmt.Errorf("%s: index %q, %d of %d", p.Name, st.LastIndexToken, st.Applied, st.Target)
			}
			token, target = st.LastIndexToken, st.Target
		}
		return nil
	})
	sc.NoErr(err, "the other loaders")
	settle(t, 35*time.Second) // the loader's event window (30 s) and more
	st, err := h.LoaderStatusOf(ctx, victim)
	sc.NoErr(err, "the loader status of %s", victim.Name)
	if st.LastIndexToken != base.LastIndexToken || st.Pushes() != base.Pushes() {
		sc.Fatalf("the change reached %s's loader while it was blocked (index %q, pushes %d to %d): the event was not lost", victim.Name, st.LastIndexToken, base.Pushes(), st.Pushes())
	}

	sc.Step("lift the block; the loader's timer repairs it within the reconcile period (%s)", interval)
	sc.NoErr(unblock(ctx), "restoring the bus NetworkPolicy")
	blocked = false
	lifted := time.Now()
	bound := interval*6/5 + 30*time.Second
	err = retryFor(ctx, bound, time.Second, func() error {
		st, err := h.LoaderStatusOf(ctx, victim)
		if err != nil {
			return err
		}
		if st.LastIndexToken != token || st.Applied != st.Target || st.Target != target || st.Pushes() < base.Pushes()+2 {
			return fmt.Errorf("index %q (want %q), %d of %d accounts (want %d), %d pushes since the block",
				st.LastIndexToken, token, st.Applied, st.Target, target, st.Pushes()-base.Pushes())
		}
		return nil
	})
	if err != nil {
		sc.Errorf("not repaired within %s of the block lifting (reconcile interval %s, ±20%%, and a request's timeout): %v", bound, interval, err)
	} else {
		sc.Logf("repaired %s after the block lifted", time.Since(lifted).Round(time.Second))
	}

	sc.Step("every bus node refuses the revoked sprout and accepts the new tenant's")
	expectBus(t, sc, h, revoked, harness.ErrBusRefused)
	expectBus(t, sc, h, fresh, nil)
}

// enrolIn mints a key in a scratch tenant and enrols a sprout in it.
func enrolIn(t *testing.T, sc *harness.Scenario, fe *harness.FullEnroller, tenantID, tok string) *harness.Enrolment {
	t.Helper()
	ctx := ctxFor(t, 10*time.Minute)
	key, err := fleet.API.MintKey(ctx, tok, tenantID, 2, 5)
	sc.NoErr(err, "minting a key in tenant %s", tenantID)
	e, err := harness.NewEnrolment("uat-ha-"+harness.Nonce(8), key.RegistrationKey)
	sc.NoErr(err, "keys")
	sc.NoErr(fe.Enrol(ctx, e), "enrolling in tenant %s", tenantID)
	return e
}

// expectBus connects e to every bus node and fails the test unless each
// answers want (nil: accepted; ErrBusRefused: refused).
func expectBus(t *testing.T, sc *harness.Scenario, h *harness.HA, e *harness.Enrolment, want error) {
	t.Helper()
	got, err := h.ConnectEveryBusNode(ctxFor(t, 5*time.Minute), e)
	sc.NoErr(err, "reaching the bus nodes")
	var names []string
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		err := got[n]
		switch {
		case want == nil && err != nil:
			sc.Errorf("bus node %s refused sprout %s of tenant %s: %v", n, e.SproutID, e.TenantID, err)
		case want != nil && !errors.Is(err, want):
			sc.Errorf("bus node %s: sprout %s of tenant %s: want %v, got %v", n, e.SproutID, e.TenantID, want, err)
		}
	}
}

func TestHAHA6_ParallelEnrolment(t *testing.T) {
	sc := harness.Begin(t, "HA6")
	f, h := haReady(t, sc)
	ctx := ctxFor(t, 60*time.Minute)
	envoys, err := h.DMZ.Pods(ctx, harness.DMZNamespace, harness.Selector("envoy"))
	sc.NoErr(err, "listing the Envoys")
	n := len(harness.Live(envoys))
	if n == 0 {
		sc.Fatalf("no Envoy pod")
	}

	sc.Step("create three tenants at once")
	type tenant struct{ id, tok string }
	var tenants []tenant
	for i := 0; i < 3; i++ {
		id, tok := scratchTenant(t, sc, fmt.Sprintf("ha6-%d", i), false)
		t.Cleanup(func() { offboard(t, id, tok) })
		tenants = append(tenants, tenant{id, tok})
	}
	for _, tn := range tenants {
		got, err := f.API.WaitTenantStatus(ctx, tn.tok, tn.id, harness.DefaultTenantTimeout, harness.TenantActive, harness.TenantFailed)
		sc.NoErr(err, "waiting for tenant %s", tn.id)
		if got.Status != harness.TenantActive {
			sc.Fatalf("tenant %s: %s (%s)", tn.id, got.Status, got.LastError)
		}
	}
	keys := []string{mintKey(t, sc, 1, 2, 500).RegistrationKey}
	for _, tn := range tenants {
		k, err := f.API.MintKey(ctx, tn.tok, tn.id, 2, 500)
		sc.NoErr(err, "a key in tenant %s", tn.id)
		keys = append(keys, k.RegistrationKey)
	}

	// Envoy admits 20 /v1/enroll requests per 60 s per Envoy
	// (deploy/helm/nats values.yaml); an enrolment is two.
	every := time.Minute / time.Duration(10*n)
	sc.Step("enrol for a minute at Envoy's admitted rate: one sprout every %s (%d Envoys), the tenants in turn", every, n)
	fe := harness.NewFullEnroller(f.Env.EnvoyURL, f.API.HTTP)
	var mu sync.Mutex
	var done []*harness.Enrolment
	var failed []string
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; time.Since(start) < time.Minute; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e, err := harness.NewEnrolment(fmt.Sprintf("uat-ha6-%d-%s", i, harness.Nonce(6)), keys[i%len(keys)])
			if err == nil {
				err = fe.Enrol(ctx, e)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed = append(failed, err.Error())
				return
			}
			done = append(done, e)
		}(i)
		time.Sleep(every)
	}
	wg.Wait()
	sc.Logf("%d enrolments in %s, %d failed", len(done), time.Since(start).Round(time.Second), len(failed))
	for _, e := range failed {
		sc.Errorf("enrolment failed: %s", e)
	}
	checkIdentities(t, sc, fe, done)
	sc.Step("every new tenant's account is on every bus node")
	seen := map[string]bool{}
	for _, e := range done {
		if e.TenantID == fleet.TenantID(1) || seen[e.TenantID] {
			continue
		}
		seen[e.TenantID] = true
		expectBus(t, sc, h, e, nil)
	}
	if len(seen) != len(tenants) {
		sc.Errorf("sprouts enrolled in %d of the %d new tenants", len(seen), len(tenants))
	}
}
