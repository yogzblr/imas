//go:build uat

package uattests

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

// result is one sprout's item from a batch, or why there is none.
type result struct {
	item harness.Item
	err  error
}

// runByFamily runs one cmd.run batch per OS family over the sprouts of
// tenant n (the command differs by family) and returns each sprout's item
// by VM name.
func runByFamily(ctx context.Context, n int, sprouts []harness.Sprout, cmd func(harness.Sprout) harness.CmdRun) map[string]result {
	out := map[string]result{}
	for _, fam := range []string{harness.FamilyLinux, harness.FamilyWindows} {
		var group []harness.Sprout
		for _, s := range sprouts {
			if s.Family() == fam && fleet.Ready(s) == nil {
				group = append(group, s)
			}
		}
		if len(group) == 0 {
			continue
		}
		b, err := fleet.Do(ctx, n, group, harness.CmdRunAction(cmd(group[0])))
		for _, s := range group {
			it, ok := b.For(s)
			switch {
			case err != nil:
				out[s.VM] = result{err: err}
			case !ok:
				out[s.VM] = result{err: fmt.Errorf("the batch has no item for asset %s", s.AssetID)}
			default:
				out[s.VM] = result{item: it}
			}
		}
	}
	return out
}

// itemOf returns a sprout's item from runByFamily, failing the test if
// there is none.
func itemOf(sc *harness.Scenario, res map[string]result, sp harness.Sprout) harness.Item {
	sc.T.Helper()
	r, ok := res[sp.VM]
	if !ok {
		sc.Fatalf("no batch ran for this sprout")
	}
	sc.NoErr(r.err, "the batch")
	return r.item
}

func TestSmokeC1_CmdRunEverySprout(t *testing.T) {
	sc := harness.Begin(t, "C1")
	f := ready(t, sc)
	f.EachTenant(t, sc, func(t *testing.T, sc *harness.Scenario, n int) {
		sprouts := f.Sprouts(harness.InTenant(n))
		sc.Step("cmd.run on every sprout of tenant %d", n)
		res := runByFamily(ctxFor(t, 10*time.Minute), n, sprouts, harness.TrueCmd)
		f.EachSprout(t, sc, sprouts, func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
			sc.Step("check the item")
			it := itemOf(sc, res, sp)
			if it.Status != harness.ItemSucceeded || it.ExitCode == nil || *it.ExitCode != 0 {
				sc.Fatalf("want succeeded with exit_code 0, got %s", it)
			}
			if it.SproutID != sp.SproutID {
				sc.Errorf("item names sprout %q, want %q", it.SproutID, sp.SproutID)
			}
		})
	})
}

func TestCoreC2_NonZeroExit(t *testing.T) {
	sc := harness.Begin(t, "C2")
	f := ready(t, sc)
	f.EachTenant(t, sc, func(t *testing.T, sc *harness.Scenario, n int) {
		sprouts := f.Sprouts(harness.InTenant(n))
		sc.Step("cmd.run exiting 7")
		res := runByFamily(ctxFor(t, 10*time.Minute), n, sprouts, func(s harness.Sprout) harness.CmdRun { return harness.ExitCmd(s, 7) })
		f.EachSprout(t, sc, sprouts, func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
			it := itemOf(sc, res, sp)
			if it.Status != harness.ItemFailed || it.Error != "command_failed" || it.ExitCode == nil || *it.ExitCode != 7 {
				sc.Fatalf("want failed command_failed exit_code 7, got %s", it)
			}
		})
	})
}

func TestCoreC3_TimeoutHonoured(t *testing.T) {
	sc := harness.Begin(t, "C3")
	f := ready(t, sc)
	sprouts := f.Sprouts(harness.InTenant(1))
	f.EachSprout(t, sc, sprouts, func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
		ctx := ctxFor(t, 10*time.Minute)
		cmd := harness.SleepCmd(sp, 90)
		cmd.TimeoutSeconds = 5
		sc.Step("cmd.run sleeping 90s with timeout_seconds 5")
		start := time.Now()
		b, err := f.Do(ctx, sp.Tenant, []harness.Sprout{sp}, harness.CmdRunAction(cmd))
		took := time.Since(start)
		sc.NoErr(err, "the batch")
		it, _ := b.For(sp)
		if it.Status == harness.ItemSucceeded {
			sc.Fatalf("a 90 second sleep succeeded under timeout_seconds 5: %s", it)
		}
		if it.Status != harness.ItemFailed {
			sc.Fatalf("want failed, got %s", it)
		}
		sc.Logf("timed out as %s after %s", it, took.Round(time.Second))
		// 5 s of command, the sprout's and farmer's reply path and the 2 s
		// poll: far below the 90 s the command would take if the timeout
		// were ignored.
		if took > 60*time.Second {
			sc.Errorf("the batch took %s; the command should have been stopped after 5s", took.Round(time.Second))
		}
	})
}

func TestCoreC4_ShellSyntaxArgsCwdRunAs(t *testing.T) {
	sc := harness.Begin(t, "C4")
	f := ready(t, sc)
	t.Run("t1_shell_syntax", func(t *testing.T) {
		ssc := harness.Begin(t, "C4").ForTenant(t, 1)
		ctx := ctxFor(t, 3*time.Minute)
		tok := token(t, ssc, 1, harness.RoleAdmin)
		assets := harness.Assets(f.Sprouts(harness.InTenant(1)))
		for _, cmd := range []string{"echo hi; id", "cat /etc/passwd | head", "echo $HOME", "ls > /tmp/x", "sh -c 'id'", "echo `id`"} {
			ssc.Step("cmd %q", cmd)
			var r *harness.Response
			var err error
			for i := 0; i < 5; i++ {
				_, r, err = f.API.PostBatch(ctx, tok, f.TenantID(1), assets, harness.CmdRunAction(harness.CmdRun{Cmd: cmd}))
				if err != nil || r.Status != http.StatusTooManyRequests {
					break
				}
				time.Sleep(2 * time.Second)
			}
			ssc.Check(r, err, http.StatusBadRequest, "invalid_request", "cmd %q without args", cmd)
		}
	})
	f.EachSprout(t, sc, f.Sprouts(harness.InTenant(1)), func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
		ctx := ctxFor(t, 15*time.Minute)
		nonce := harness.Nonce(8)
		argsPath := sp.TempPath("imas-uat-c4-args-" + nonce)
		cwdName := "imas-uat-c4-cwd-" + nonce
		runAsPath := sp.TempPath("imas-uat-c4-runas-" + nonce)

		sc.Step("args")
		b, err := f.Do(ctx, sp.Tenant, []harness.Sprout{sp}, harness.CmdRunAction(harness.TouchCmd(sp, argsPath)))
		sc.NoErr(err, "the args batch")
		sc.ExpectItem(b, sp, harness.ItemSucceeded, "")

		sc.Step("cwd")
		c := harness.TouchCmd(sp, cwdName)
		c.CWD = sp.TempDir()
		b, err = f.Do(ctx, sp.Tenant, []harness.Sprout{sp}, harness.CmdRunAction(c))
		sc.NoErr(err, "the cwd batch")
		sc.ExpectItem(b, sp, harness.ItemSucceeded, "")

		sc.Step("run_as")
		c = harness.TouchCmd(sp, runAsPath)
		c.RunAs = "nobody"
		b, err = f.Do(ctx, sp.Tenant, []harness.Sprout{sp}, harness.CmdRunAction(c))
		sc.NoErr(err, "the run_as batch")
		runAsItem, _ := b.For(sp)

		sc.Step("check the files on the host")
		res, err := f.OnHost(ctx, sp, harness.MultiFileState([]string{argsPath, sp.TempPath(cwdName), runAsPath}))
		sc.NoErr(err, "vmctl.sh run")
		exists, err := harness.ParseMultiFileState(res, 3)
		sc.NoErr(err, "reading the file check")
		if !exists[0] {
			sc.Errorf("args: %s was not created", argsPath)
		}
		if !exists[1] {
			sc.Errorf("cwd: %s was not created in %s", cwdName, sp.TempDir())
		}
		if sp.IsWindows() {
			// internal/ingredients/cmd/runas_windows.go: run_as is not
			// supported on Windows, so the command must fail, not run as
			// SYSTEM.
			if runAsItem.Status != harness.ItemFailed || exists[2] {
				sc.Errorf("run_as on Windows: want the item failed and no file, got %s (file exists: %v)", runAsItem, exists[2])
			}
			return
		}
		if runAsItem.Status != harness.ItemSucceeded {
			sc.Fatalf("run_as nobody: %s", runAsItem)
		}
		fi, err := f.File(ctx, sp, runAsPath)
		sc.NoErr(err, "checking the run_as file")
		if !fi.Exists || fi.Owner != "nobody" {
			sc.Errorf("run_as: %s is owned by %q (exists %v), want nobody", runAsPath, fi.Owner, fi.Exists)
		}
	})
}

func TestCoreC5_UnknownAssetUnresolved(t *testing.T) {
	sc := harness.Begin(t, "C5")
	f := ready(t, sc)
	f.EachTenant(t, sc, func(t *testing.T, sc *harness.Scenario, n int) {
		ctx := ctxFor(t, 5*time.Minute)
		unknown := "uat-c5-none-" + harness.Nonce(8)
		assets := []string{unknown}
		// The other tenant's asset IDs are unknown here too.
		for _, s := range f.Sprouts() {
			if s.Tenant != n {
				assets = append(assets, s.AssetID)
				break
			}
		}
		sc.Step("cmd.run on %v", assets)
		b, err := f.DoAssets(ctx, n, assets, harness.CmdRunAction(harness.CmdRun{Cmd: "id -u"}), harness.DefaultBatchTimeout)
		sc.NoErr(err, "the batch")
		for _, a := range assets {
			it, ok := b.Item(a)
			if !ok {
				sc.Errorf("no item for %s", a)
				continue
			}
			if it.Status != harness.ItemUnresolved || it.SproutID != "" {
				sc.Errorf("asset %s: want unresolved with no sprout, got %s", a, it)
			}
		}
	})
}

func TestCoreC6_StoppedSproutUnreachable(t *testing.T) {
	sc := harness.Begin(t, "C6")
	f := ready(t, sc)
	f.EachSprout(t, sc, f.Sprouts(harness.InTenant(1)), func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
		ctx := ctxFor(t, 30*time.Minute)
		sc.Step("stop the sprout service (vmctl.sh stop-sprout)")
		sc.NoErr(f.VM.StopSprout(ctx, sp.VM), "stopping the sprout")
		started := false
		t.Cleanup(func() {
			if !started {
				_ = f.VM.StartSprout(cleanupCtx(), sp.VM)
			}
		})
		sc.Step("cmd.run on the stopped sprout")
		b, err := f.Do(ctx, sp.Tenant, []harness.Sprout{sp}, harness.CmdRunAction(harness.TrueCmd(sp)))
		sc.NoErr(err, "the batch")
		it, _ := b.For(sp)
		if it.Status != harness.ItemFailed || it.Error != "sprout_unreachable" {
			sc.Errorf("want failed sprout_unreachable, got %s", it)
		}
		sc.Step("start the sprout again (vmctl.sh start-sprout)")
		sc.NoErr(f.VM.StartSprout(ctx, sp.VM), "starting the sprout")
		started = true
		sc.Step("wait until it runs a job again")
		sc.NoErr(f.WaitRuns(ctx, []harness.Sprout{sp}, harness.DefaultConnectTimeout), "after restart")
	})
}

func TestCoreC7_BatchPerItemResults(t *testing.T) {
	sc := harness.Begin(t, "C7")
	f := ready(t, sc)
	f.EachTenant(t, sc, func(t *testing.T, sc *harness.Scenario, n int) {
		ctx := ctxFor(t, 15*time.Minute)
		sprouts := f.Sprouts(harness.InTenant(n))
		if len(sprouts) == 0 {
			sc.Skipf("tenant %d has no sprouts in uat.json", n)
		}
		unknown := "uat-c7-none-" + harness.Nonce(8)
		assets := append(harness.Assets(sprouts), unknown, sprouts[0].AssetID) // a duplicate, too

		sc.Step("one hostname batch over every sprout of the tenant, an unknown asset and a duplicate")
		same, err := f.DoAssets(ctx, n, assets, harness.CmdRunAction(harness.CmdRun{Cmd: "hostname"}), harness.DefaultBatchTimeout)
		sc.NoErr(err, "the batch")
		if len(same.Items) != len(sprouts)+1 {
			sc.Errorf("%d items for %d distinct asset IDs", len(same.Items), len(sprouts)+1)
		}
		if it, ok := same.Item(unknown); !ok || it.Status != harness.ItemUnresolved {
			sc.Errorf("unknown asset: %+v (found %v), want unresolved", it, ok)
		}

		sc.Step("one /bin/true batch: runs on Linux, fails on Windows")
		mixed, mixedErr := f.DoAssets(ctx, n, harness.Assets(sprouts), harness.CmdRunAction(harness.CmdRun{Cmd: "/bin/true"}), harness.DefaultBatchTimeout)

		f.EachSprout(t, sc, sprouts, func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
			sc.Step("hostname item")
			it := sc.ExpectItem(same, sp, harness.ItemSucceeded, "")
			if it.SproutID != sp.SproutID {
				sc.Errorf("item names sprout %q, want %q", it.SproutID, sp.SproutID)
			}
			sc.Step("/bin/true item")
			sc.NoErr(mixedErr, "the mixed batch")
			it, ok := mixed.For(sp)
			switch {
			case !ok:
				sc.Errorf("no item")
			case sp.IsWindows() && (it.Status != harness.ItemFailed || it.Error == ""):
				sc.Errorf("Windows has no /bin/true: want failed with an error code, got %s", it)
			case !sp.IsWindows() && it.Status != harness.ItemSucceeded:
				sc.Errorf("want succeeded, got %s", it)
			}
		})
	})
}

func TestCoreC8_TenantRateLimit(t *testing.T) {
	sc := harness.Begin(t, "C8")
	ctx := ctxFor(t, 3*time.Minute)
	tok2 := token(t, sc, 2, harness.RoleAdmin)
	tok1 := token(t, sc, 1, harness.RoleAdmin)
	unknown := []string{"uat-c8-none-" + harness.Nonce(8)}
	act := harness.CmdRunAction(harness.CmdRun{Cmd: "id -u"})

	sc.Step("let the bucket refill")
	time.Sleep(6 * time.Second)
	sc.Step("post 15 batches back to back in tenant 2")
	accepted, limited := 0, 0
	for i := 0; i < 15; i++ {
		_, r, err := fleet.API.PostBatch(ctx, tok2, fleet.TenantID(2), unknown, act)
		sc.NoErr(err, "POST actions")
		switch {
		case r.Status == http.StatusAccepted:
			accepted++
		case r.Is(http.StatusTooManyRequests, "rate_limited"):
			limited++
		default:
			sc.Fatalf("request %d: %s", i+1, r)
		}
	}
	sc.Logf("%d accepted, %d rate limited (1/s, burst 5, per saasapi pod)", accepted, limited)
	if limited == 0 {
		sc.Errorf("15 back-to-back batches were all accepted; want 429 rate_limited past the burst")
	}
	if accepted < 5 {
		sc.Errorf("only %d accepted; the burst is 5", accepted)
	}
	sc.Step("tenant 1 posts while tenant 2 is limited")
	_, r, err := fleet.API.PostBatch(ctx, tok1, fleet.TenantID(1), unknown, act)
	sc.Check(r, err, http.StatusAccepted, "", "tenant 1's batch while tenant 2 is rate limited")
}
