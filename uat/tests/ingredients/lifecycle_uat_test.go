//go:build uat

package ingredients

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

// windowsLifecycleSkip is why L4 and L5 don't run on the Windows sprouts.
const windowsLifecycleSkip = "the Windows MSI comes from the NuGet feed through the imas_sprout role (win_package), " +
	"which this suite doesn't drive (as S6), and a pre-release MSI carries no rc suffix in its ProductVersion; " +
	"L4 and L5 run on the Linux sprouts"

// upgradeFrom returns upgrade_from_tag, skipping the test when it is empty.
func upgradeFrom(sc *harness.Scenario) string {
	from := os.Getenv(EnvUpgradeFromTag)
	if from == "" {
		sc.Skipf("upgrade_from_tag is empty: %s needs the earlier release to start from (the workflow input upgrade_from_tag, %s)", sc.ID, EnvUpgradeFromTag)
	}
	if _, _, err := ParseReleaseTag(from); err != nil {
		sc.Fatalf("upgrade_from_tag: %v", err)
	}
	return from
}

// installEarlier downgrades a sprout to the earlier release in place and
// waits until that release is connected and runs a job under the same
// sprout ID: the earlier release, enrolled. It returns the package
// version installed before (the release under test) and the config's
// hash and sproutid on the earlier release.
func installEarlier(ctx context.Context, f *harness.Fleet, sc *harness.Scenario, sp harness.Sprout, from string) (cur, cfgSHA, cfgID string) {
	sc.Step("install %s with the package manager", from)
	script, err := DowngradeScript(from)
	sc.NoErr(err, "building the install script")
	res, err := f.OnHost(ctx, sp, harness.HostScript{Linux: script})
	sc.NoErr(err, "vmctl.sh run")
	cur, _ = res.Value("CUR_VERSION")
	old, _ := res.Value("OLD_VERSION")
	switch res.ExitCode {
	case 0:
	case 20:
		sc.Fatalf("the repository the role configured has no imas-sprout package of %s: %s", from, clip(res.Output, 600))
	case 21:
		sc.Fatalf("upgrade_from_tag %s is the release already installed (%s): it must name an earlier release", from, cur)
	default:
		sc.Fatalf("installing %s (package %s over %s) exited %d: %s", from, old, cur, res.ExitCode, clip(res.Output, 800))
	}
	if now, _ := res.Value("NOW_VERSION"); !PackageVersionIs(now, from) {
		sc.Fatalf("after installing %s the package version is %q", from, now)
	}
	before, _ := res.Value("CFG_SHA_BEFORE")
	cfgSHA, _ = res.Value("CFG_SHA_OLD")
	idBefore, _ := res.Value("SPROUTID_BEFORE")
	cfgID, _ = res.Value("SPROUTID_OLD")
	if before != cfgSHA || idBefore != cfgID {
		sc.Errorf("installing the earlier release changed /etc/imas/sprout (sha256 %s -> %s, sproutid %q -> %q)", before, cfgSHA, idBefore, cfgID)
	}
	sc.Step("%s is enrolled: it reconnects and runs a job under the same sprout ID", from)
	sc.NoErr(f.WaitRuns(ctx, []harness.Sprout{sp}, harness.DefaultConnectTimeout), "the earlier release running a job")
	claims, err := f.HostClaims(ctx, sp)
	sc.NoErr(err, "reading the gateway JWT's claims")
	if got := harness.ClaimString(claims, "sprout_id"); got != sp.SproutID {
		sc.Errorf("sprout_id on the earlier release %q, want %q", got, sp.SproutID)
	}
	return cur, cfgSHA, cfgID
}

// restore puts the release under test back if a test left the sprout on
// another version, so the tests after it run on the right one.
func restore(f *harness.Fleet, sp harness.Sprout, version string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	res, err := f.OnHost(ctx, sp, harness.PackageInfo())
	if err == nil {
		if v, _ := res.Value("PKG_VERSION"); v == version {
			return
		}
	}
	_, _ = f.OnHost(ctx, sp, harness.HostScript{Linux: UpgradeScript(version)})
	_ = f.WaitRuns(ctx, []harness.Sprout{sp}, harness.DefaultConnectTimeout)
}

// TestLifecycleL4_PackageUpgrade: on each tenant 1 Linux sprout, install
// the package of the earlier release (upgrade_from_tag) over the one
// under test, see it connected and running a job under the same sprout ID,
// then upgrade to the release under test with the package manager and
// assert /etc/imas/sprout and the sproutid are kept, the service runs and
// a job runs.
//
// "Enrols" here means the earlier release comes up with the identity the
// run already enrolled: a fresh enrolment would need the host's old
// sprout record deleted, and saasapi has no route for that (the API gap
// recorded by UAT.5 for S6); a purge would enrol it as <sprout_id>_1.
func TestLifecycleL4_PackageUpgrade(t *testing.T) {
	sc := harness.Begin(t, "L4")
	from := upgradeFrom(sc)
	f := ready(t, sc)
	sprouts := f.Sprouts(harness.InTenant(1))
	if len(sprouts) == 0 {
		// A rig without the sprouts a scenario needs reports a skip with
		// the reason, never a pass or a spurious failure.
		sc.Skipf("uat.json has no tenant 1 sprout")
	}
	f.EachSprout(t, sc, sprouts, func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
		if sp.IsWindows() {
			sc.Skipf("%s", windowsLifecycleSkip)
		}
		ctx := ctxFor(t, 45*time.Minute)
		cur, cfgSHA, cfgID := installEarlier(ctx, f, sc, sp, from)
		t.Cleanup(func() {
			if t.Failed() {
				restore(f, sp, cur)
			}
		})

		sc.Step("upgrade to the release under test (%s) with the package manager", cur)
		res, err := f.OnHost(ctx, sp, harness.HostScript{Linux: UpgradeScript(cur)})
		sc.NoErr(err, "vmctl.sh run")
		if res.ExitCode != 0 {
			sc.Fatalf("the upgrade exited %d: %s", res.ExitCode, clip(res.Output, 800))
		}
		if v, _ := res.Value("NEW_VERSION"); v != cur {
			sc.Errorf("after the upgrade the package version is %q, want %q", v, cur)
		}
		if f.Env.ReleaseTag != "" && !PackageVersionIs(cur, f.Env.ReleaseTag) {
			sc.Errorf("the version upgraded to, %q, is not release %s", cur, f.Env.ReleaseTag)
		}
		if got, _ := res.Value("CFG_SHA_NEW"); got != cfgSHA {
			sc.Errorf("the upgrade changed /etc/imas/sprout (sha256 %s -> %s)", cfgSHA, got)
		}
		if got, _ := res.Value("SPROUTID_NEW"); got != cfgID {
			sc.Errorf("the upgrade changed the config's sproutid %q -> %q", cfgID, got)
		}
		if s, _ := res.Value("SERVICE"); s != "active" {
			sc.Errorf("the imas-sprout service is %q after the upgrade", s)
		}

		sc.Step("a job runs after the upgrade, under the same sprout ID")
		sc.NoErr(f.WaitRuns(ctx, []harness.Sprout{sp}, harness.DefaultConnectTimeout), "after the upgrade")
		claims, err := f.HostClaims(ctx, sp)
		sc.NoErr(err, "reading the gateway JWT's claims")
		if got := harness.ClaimString(claims, "sprout_id"); got != sp.SproutID {
			sc.Errorf("sprout_id after the upgrade %q, want %q", got, sp.SproutID)
		}
		if got := harness.ClaimString(claims, "tenant_id"); got != f.TenantID(sp.Tenant) {
			sc.Errorf("tenant_id after the upgrade %q, want %q", got, f.TenantID(sp.Tenant))
		}
	})
}

// fleetVersion is one row of GET /v1/versions.
type fleetVersion struct {
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Revoked bool   `json:"revoked"`
}

// updatePolicy is GET/PATCH .../update-policy.
type updatePolicy struct {
	ApprovedVersion *string `json:"approved_version"`
	AutoUpdate      bool    `json:"auto_update"`
}

// TestLifecycleL5_SelfUpdate runs one self update cycle, only when
// IMAS_UAT_DISPATCH_FLAGS says the dispatch flags are on (opt in, UAT
// only; the workflow's dispatch_flags turns them on in the core hub): one
// tenant 1 Linux sprout is put on the earlier release, the tenant approves
// the release under test, POST .../sprouts/updates sends it, and the item
// must succeed (the sprout reconnects reporting the target), with the
// package, the config, the sprout ID and a job checked on the host
// afterwards.
//
// Then the P22 trust path: the sprout's keyring (/etc/imas/fleet-signing-
// keys.asc) is the repo's gpg-public-key.asc, the one it verified the
// release's GPG-signed checksums.txt with; and a release whose checksums.txt
// was altered is refused. The test registers the release's packages and
// checksums.txt under a scratch version through the operator API, its
// version rewritten in every file name, with the release's own
// checksums.txt.sig (uat/hub/core/operator-release.sh post-altered),
// approves it and rolls it out: the item must fail, the sprout's job log
// must say the signature did not verify, nothing may be downloaded or
// staged, and the sprout must still run the release under test.
func TestLifecycleL5_SelfUpdate(t *testing.T) {
	sc := harness.Begin(t, "L5")
	if !FlagOn(os.Getenv(EnvDispatchFlags)) {
		sc.Skipf("the fleet update dispatch flags are off for this run: L5 runs only when %s=on says saasapi has SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED=true and farmer IMAS_SELF_UPDATE_ENABLED=true (opt in, UAT only)", EnvDispatchFlags)
	}
	from := upgradeFrom(sc)
	f := ready(t, sc)
	target := f.Env.ReleaseTag
	if target == "" {
		sc.Skipf("%s is empty: the self update's target_version is the release under test", harness.EnvReleaseTag)
	}
	var sp harness.Sprout
	for _, os := range []string{harness.OSUbuntu, harness.OSAlma} {
		if ss := f.Sprouts(harness.InTenant(1), harness.WithOS(os)); len(ss) > 0 {
			sp = ss[0]
			break
		}
	}
	if sp.VM == "" {
		sc.Skipf("no tenant 1 Linux sprout in uat.json (%s)", windowsLifecycleSkip)
	}
	t.Run(sp.Name(), func(t *testing.T) {
		sc := sc.ForSprout(t, sp)
		if err := f.Ready(sp); err != nil {
			sc.Fatalf("sprout not ready: %v", err)
		}
		ctx := ctxFor(t, 90*time.Minute)
		tid := f.TenantID(1)
		tok, err := f.Admin(ctx, 1)
		sc.NoErr(err, "tenant 1's admin token")

		sc.Step("the fleet catalog lists %s", target)
		r, err := f.API.Do(ctx, harness.Request{Method: http.MethodGet, Path: "/v1/versions", Token: tok})
		sc.Expect(r, err, http.StatusOK, "", "GET /v1/versions")
		var cat struct {
			Versions []fleetVersion `json:"versions"`
		}
		sc.NoErr(r.Decode(&cat), "decoding the catalog")
		listed := false
		for _, v := range cat.Versions {
			if v.Version == target && !v.Revoked {
				listed = true
				sc.Logf("catalog row %s %s/%s", v.Version, v.OS, v.Arch)
			}
		}
		if !listed {
			sc.Fatalf("release %s is not in the fleet catalog (or is revoked): register it (the farmer chart's sprout release hook) before L5", target)
		}

		cur, cfgSHA, cfgID := installEarlier(ctx, f, sc, sp, from)
		t.Cleanup(func() { restore(f, sp, cur) })

		sc.Step("approve %s for tenant 1", target)
		r, err = f.API.Do(ctx, harness.Request{Method: http.MethodGet, Path: harness.TenantPath(tid, "update-policy"), Token: tok})
		sc.Expect(r, err, http.StatusOK, "", "GET update-policy")
		var prev updatePolicy
		sc.NoErr(r.Decode(&prev), "decoding the update policy")
		t.Cleanup(func() {
			cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			ctok, err := f.Admin(cctx, 1)
			if err != nil {
				return
			}
			_, _ = f.API.Do(cctx, harness.Request{Method: http.MethodPatch, Path: harness.TenantPath(tid, "update-policy"), Token: ctok,
				Body: map[string]any{"approved_version": prev.ApprovedVersion, "auto_update": prev.AutoUpdate}})
		})
		r, err = f.API.Do(ctx, harness.Request{Method: http.MethodPatch, Path: harness.TenantPath(tid, "update-policy"), Token: tok,
			Body: map[string]any{"approved_version": target, "auto_update": false}})
		sc.Expect(r, err, http.StatusOK, "", "PATCH update-policy approved_version=%s", target)

		sc.Step("start the update rollout")
		r, err = f.API.Do(ctx, harness.Request{Method: http.MethodPost, Path: harness.TenantPath(tid, "sprouts", "updates"), Token: tok,
			Body: map[string]any{"asset_ids": []string{sp.AssetID}, "target_version": target, "batch_size": 1}})
		if err == nil && r.Status == http.StatusNotFound && r.Error.Code == "" {
			sc.Fatalf("POST .../sprouts/updates is not registered: saasapi runs without SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED=true although %s says the flags are on", EnvDispatchFlags)
		}
		sc.Expect(r, err, http.StatusAccepted, "", "POST .../sprouts/updates")
		var created struct {
			BatchID string `json:"batch_id"`
		}
		sc.NoErr(r.Decode(&created), "decoding the batch id")

		sc.Step("wait for the rollout (batch %s)", created.BatchID)
		b := waitRollout(ctx, f, sc, tid, created.BatchID)
		sc.ExpectItem(&b, sp, harness.ItemSucceeded, "")

		sc.Step("the sprout runs %s with its config and identity kept", target)
		res, err := f.OnHost(ctx, sp, harness.PackageInfo())
		sc.NoErr(err, "reading the package on the host")
		if v, _ := res.Value("PKG_VERSION"); !PackageVersionIs(v, target) {
			sc.Errorf("after the self update the package version is %q, not release %s", v, target)
		}
		if s, _ := res.Value("SERVICE"); s != "active" {
			sc.Errorf("the imas-sprout service is %q after the self update", s)
		}
		res, err = f.OnHost(ctx, sp, harness.HostScript{Linux: `want=""
` + shVersionFns + `cfg_state NEW`})
		sc.NoErr(err, "reading the config on the host")
		if got, _ := res.Value("CFG_SHA_NEW"); got != cfgSHA {
			sc.Errorf("the self update changed /etc/imas/sprout (sha256 %s -> %s)", cfgSHA, got)
		}
		if got, _ := res.Value("SPROUTID_NEW"); got != cfgID {
			sc.Errorf("the self update changed the config's sproutid %q -> %q", cfgID, got)
		}
		sc.NoErr(f.WaitRuns(ctx, []harness.Sprout{sp}, harness.DefaultConnectTimeout), "a job after the self update")
		claims, err := f.HostClaims(ctx, sp)
		sc.NoErr(err, "reading the gateway JWT's claims")
		if got := harness.ClaimString(claims, "sprout_id"); got != sp.SproutID {
			sc.Errorf("sprout_id after the self update %q, want %q", got, sp.SproutID)
		}

		// --- P22: the keyring, and a release with an altered checksums.txt.
		sc.Step("the sprout's keyring %s is the repo's %s", SproutFleetKeyring, RepoFleetKeyring)
		repoKeyring, err := os.ReadFile(filepath.Join(repoRoot(sc), RepoFleetKeyring))
		sc.NoErr(err, "reading the repo's %s", RepoFleetKeyring)
		res, err = f.OnHost(ctx, sp, harness.HostScript{Linux: RefusalCheckScript("none")})
		sc.NoErr(err, "reading the keyring on the host")
		if got, read := res.Value("KEYRING_SHA"); got != fmt.Sprintf("%x", sha256.Sum256(repoKeyring)) {
			sc.Errorf("%s on the host has sha256 %q (read: %v), want the repo's %s, %x", SproutFleetKeyring, got, read, RepoFleetKeyring, sha256.Sum256(repoKeyring))
		}

		scratch, err := AlteredScratchVersion(target)
		sc.NoErr(err, "the scratch version")
		if !f.CanReachOperatorAPI() {
			sc.Fatalf("%v", harness.ErrNoOperatorAPI)
		}
		sc.Step("register %s with %s's checksums.txt altered and its signature kept (operator API)", scratch, target)
		ans, err := f.PostAlteredRelease(ctx, scratch)
		sc.NoErr(err, "operator-release.sh post-altered %s", scratch)
		if ans.Status != http.StatusOK && ans.Status != http.StatusCreated {
			sc.Fatalf("the operator API refused the altered pair for %s: %d %s (saasapi checks only its form, never the signature)", scratch, ans.Status, ans.Body)
		}
		sc.Step("approve %s for tenant 1 and roll it out", scratch)
		r, err = f.API.Do(ctx, harness.Request{Method: http.MethodPatch, Path: harness.TenantPath(tid, "update-policy"), Token: tok,
			Body: map[string]any{"approved_version": scratch, "auto_update": false}})
		sc.Expect(r, err, http.StatusOK, "", "PATCH update-policy approved_version=%s", scratch)
		r, err = f.API.Do(ctx, harness.Request{Method: http.MethodPost, Path: harness.TenantPath(tid, "sprouts", "updates"), Token: tok,
			Body: map[string]any{"asset_ids": []string{sp.AssetID}, "target_version": scratch, "batch_size": 1}})
		sc.Expect(r, err, http.StatusAccepted, "", "POST .../sprouts/updates to %s", scratch)
		var altered struct {
			BatchID string `json:"batch_id"`
		}
		sc.NoErr(r.Decode(&altered), "decoding the batch id")
		ab := waitRollout(ctx, f, sc, tid, altered.BatchID)
		it := sc.ExpectItem(&ab, sp, harness.ItemFailed, "job_failed")
		if !jidRe.MatchString(it.JID) {
			sc.Fatalf("the refused update's item has no usable jid (%q): %s", it.JID, it)
		}

		sc.Step("the sprout refused %s: the signature did not verify, nothing was downloaded or installed", scratch)
		res, err = f.OnHost(ctx, sp, harness.HostScript{Linux: RefusalCheckScript(it.JID)})
		sc.NoErr(err, "reading the refused job on the host")
		logTail, _ := res.Value("JOBLOG_TAIL")
		if v, _ := res.Value("JOBLOG"); v != "present" {
			sc.Errorf("no job log %s/%s.jsonl on the sprout", SproutJobLogDir, it.JID)
		}
		if v, _ := res.Value("SIG_REFUSED"); v != "yes" {
			sc.Errorf("the refused job's log does not say %q: %s", SignatureRefusalMsg, logTail)
		}
		if v, _ := res.Value("DOWNLOADED"); v != "no" {
			sc.Errorf("the refused job downloaded a package: %s", logTail)
		}
		if v, _ := res.Value("STAGED"); v != "0" {
			sc.Errorf("%s holds %s entries after the refusal, want none", SproutStageDir, v)
		}
		if v, _ := res.Value("PKG_VERSION"); !PackageVersionIs(v, target) {
			sc.Errorf("after the refusal the package version is %q, want release %s still", v, target)
		}
		sc.NoErr(f.WaitRuns(ctx, []harness.Sprout{sp}, harness.DefaultConnectTimeout), "a job after the refused update")
	})
}

// waitRollout polls an update batch until it completes (40 minutes at most).
func waitRollout(ctx context.Context, f *harness.Fleet, sc *harness.Scenario, tid, batchID string) harness.Batch {
	tok, err := f.Admin(ctx, 1)
	sc.NoErr(err, "tenant 1's admin token")
	var b harness.Batch
	var r *harness.Response
	deadline := time.Now().Add(40 * time.Minute)
	for {
		r, err = f.API.Do(ctx, harness.Request{Method: http.MethodGet, Path: harness.TenantPath(tid, "sprouts", "updates", batchID), Token: tok})
		if err == nil && r.Status == http.StatusOK && r.Decode(&b) == nil && b.Status == harness.BatchCompleted {
			return b
		}
		if time.Now().After(deadline) {
			sc.Fatalf("the rollout %s didn't complete in 40 minutes: last answer %s, items %+v", batchID, r, b.Items)
		}
		select {
		case <-ctx.Done():
			sc.Fatalf("waiting for the rollout %s: %v", batchID, ctx.Err())
		case <-time.After(15 * time.Second):
		}
	}
}

// repoRoot is the repository checkout the tests run from (the directory
// holding go.mod above this package).
func repoRoot(sc *harness.Scenario) string {
	dir, err := os.Getwd()
	sc.NoErr(err, "the working directory")
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		if filepath.Dir(d) == d {
			sc.Fatalf("no go.mod above %s", dir)
		}
	}
}
