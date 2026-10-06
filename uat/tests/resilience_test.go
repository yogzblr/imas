//go:build uat

package uattests

import (
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

func TestResilienceL1_RebootSurvived(t *testing.T) {
	sc := harness.Begin(t, "L1")
	f := ready(t, sc)
	f.EachSprout(t, sc, f.Sprouts(), func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
		ctx := ctxFor(t, 45*time.Minute)
		sc.Step("baseline: a job runs")
		sc.NoErr(f.WaitRuns(ctx, []harness.Sprout{sp}, 3*time.Minute), "before the reboot")
		sc.Step("reboot the VM (vmctl.sh restart)")
		sc.NoErr(f.VM.Restart(ctx, sp.VM), "restarting the VM")
		sc.Step("wait until it is connected again")
		sc.NoErr(f.WaitConnected(ctx, []harness.Sprout{sp}, harness.DefaultConnectTimeout), "reconnecting")
		sc.Step("wait until it runs a job")
		sc.NoErr(f.WaitRuns(ctx, []harness.Sprout{sp}, harness.DefaultConnectTimeout), "after the reboot")
	})
}

// restartAndRecover restarts hub workloads through vmctl.sh, then checks
// every sprout runs a job again.
func restartAndRecover(t *testing.T, sc *harness.Scenario, workloads ...string) {
	f := ready(t, sc)
	ctx := ctxFor(t, 45*time.Minute)
	sprouts := f.Sprouts()
	sc.Step("baseline: every sprout runs a job")
	sc.NoErr(f.WaitRuns(ctx, sprouts, 5*time.Minute), "before the restart")
	for _, w := range workloads {
		c, err := f.RestartCommand(w)
		sc.NoErr(err, "the %s restart command", w)
		sc.Step("restart %s on %s (vmctl.sh run)", w, c.VM)
		sc.NoErr(f.RestartWorkload(ctx, w), "restarting %s", w)
	}
	f.EachSprout(t, sc, sprouts, func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
		sc.Step("wait until it runs a job")
		sc.NoErr(f.WaitRuns(ctx, []harness.Sprout{sp}, harness.DefaultConnectTimeout), "after the restart")
		sc.Step("and is connected")
		sc.NoErr(f.WaitConnected(ctx, []harness.Sprout{sp}, 3*time.Minute), "connected")
	})
}

func TestResilienceL2_FarmerRestart(t *testing.T) {
	restartAndRecover(t, harness.Begin(t, "L2"), "farmer")
}

func TestResilienceL3_BusAndEnvoyRestart(t *testing.T) {
	restartAndRecover(t, harness.Begin(t, "L3"), "farmerbus", "envoy")
}
