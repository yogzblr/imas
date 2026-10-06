//go:build uat

package uattests

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

func TestSmokeS1_SproutEnrolledThroughEnvoy(t *testing.T) {
	sc := harness.Begin(t, "S1")
	f := ready(t, sc)
	f.EachSprout(t, sc, f.Sprouts(), func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
		ctx := ctxFor(t, 15*time.Minute)
		tok := token(t, sc, sp.Tenant, harness.RoleAdmin)

		sc.Step("the package is installed and the service runs")
		res, err := f.OnHost(ctx, sp, harness.PackageInfo())
		sc.NoErr(err, "vmctl.sh run")
		ver, _ := res.Value("PKG_VERSION")
		svc, _ := res.Value("SERVICE")
		farmer, _ := res.Value("FARMER")
		if ver == "" {
			sc.Errorf("imas-sprout is not installed")
		} else if f.Env.ReleaseTag != "" && !versionMatches(f.Env.ReleaseTag, ver, sp.IsWindows()) {
			sc.Errorf("installed version %q is not release %s", ver, f.Env.ReleaseTag)
		}
		if svc != "active" {
			sc.Errorf("the imas-sprout service is %q", svc)
		}

		sc.Step("it enrolled through Envoy")
		envoyHost, _, _ := f.Env.SproutEnvoyHostPort()
		dmz := f.Env.UAT.DMZ
		if !slices.Contains([]string{envoyHost, dmz.FQDN, dmz.PrivateIP, dmz.PublicIP}, farmer) || farmer == "" {
			sc.Errorf("farmerinterface is %q, not Envoy in the DMZ (%s)", farmer, envoyHost)
		}

		sc.Step("its gateway JWT names its own tenant and sprout")
		claims, err := f.HostClaims(ctx, sp)
		sc.NoErr(err, "reading the gateway JWT's claims")
		if got := harness.ClaimString(claims, "tenant_id"); got != f.TenantID(sp.Tenant) {
			sc.Errorf("gateway JWT tenant_id %q, want tenant %d (%s)", got, sp.Tenant, f.TenantID(sp.Tenant))
		}
		if got := harness.ClaimString(claims, "sprout_id"); got != sp.SproutID {
			sc.Errorf("gateway JWT sprout_id %q, want %q", got, sp.SproutID)
		}

		sc.Step("saasapi sees it connected in its tenant")
		sc.NoErr(f.WaitConnected(ctx, []harness.Sprout{sp}, 3*time.Minute), "connected")
		lk, r, err := f.API.LookupAssets(ctx, tok, f.TenantID(sp.Tenant), []string{sp.AssetID})
		sc.Expect(r, err, http.StatusOK, "", "lookup")
		if got, ok := lk.Find(sp.AssetID); !ok || got.SproutID != sp.SproutID || got.KeyState != "accepted" || !got.Connected {
			sc.Errorf("lookup: %+v (found %v), want sprout %s accepted and connected", got, ok, sp.SproutID)
		}
	})
}

// versionMatches compares an installed package version with a release
// tag: deb "0.1.0~rc.4+git" or "0.1.0-rc.4+git", rpm "0.1.0~rc.4+git-1",
// and on Windows the MSI's ProductVersion, which has no pre-release part.
func versionMatches(tag, installed string, windows bool) bool {
	want := strings.TrimPrefix(tag, "v")
	core, pre, _ := strings.Cut(want, "-")
	got := strings.NewReplacer("~", "-", "_", "-").Replace(installed)
	if i := strings.IndexByte(got, '+'); i >= 0 {
		got = got[:i]
	}
	if windows {
		return strings.HasPrefix(got, core)
	}
	if pre == "" {
		return got == core || strings.HasPrefix(got, core+"-")
	}
	return strings.HasPrefix(got, core+"-"+pre)
}

func TestCoreS2_SameSproutIDPerTenant(t *testing.T) {
	sc := harness.Begin(t, "S2")
	f := ready(t, sc)
	ran := false
	for _, osName := range []string{harness.OSUbuntu, harness.OSAlma, harness.OSWindows} {
		a := f.Sprouts(harness.InTenant(1), harness.WithOS(osName))
		b := f.Sprouts(harness.InTenant(2), harness.WithOS(osName))
		if len(a) == 0 || len(b) == 0 {
			continue
		}
		ran = true
		s1, s2 := a[0], b[0]
		t.Run(osName, func(t *testing.T) {
			t.Parallel()
			osc := sc.ForSprout(t, harness.Sprout{OS: osName})
			ctx := ctxFor(t, 20*time.Minute)
			for _, s := range []harness.Sprout{s1, s2} {
				if err := f.Ready(s); err != nil {
					osc.Fatalf("%s not ready: %v", s.VM, err)
				}
			}
			osc.Step("both tenants' sprouts share a sprout ID")
			if s1.SproutID != s2.SproutID {
				osc.Fatalf("%s is %q and %s is %q: the contract gives both tenants' %s sprouts the same sproutid, which this scenario needs", s1.VM, s1.SproutID, s2.VM, s2.SproutID, osName)
			}
			nonce := harness.Nonce(8)
			m1, m2 := s1.TempPath("imas-uat-s2-t1-"+nonce), s2.TempPath("imas-uat-s2-t2-"+nonce)
			osc.Step("tenant 1 touches %s through %s", m1, s1.AssetID)
			bt, err := f.Do(ctx, 1, []harness.Sprout{s1}, harness.CmdRunAction(harness.TouchCmd(s1, m1)))
			osc.NoErr(err, "tenant 1's batch")
			osc.ExpectItem(bt, s1, harness.ItemSucceeded, "")
			osc.Step("tenant 2 touches %s through %s", m2, s2.AssetID)
			bt, err = f.Do(ctx, 2, []harness.Sprout{s2}, harness.CmdRunAction(harness.TouchCmd(s2, m2)))
			osc.NoErr(err, "tenant 2's batch")
			osc.ExpectItem(bt, s2, harness.ItemSucceeded, "")

			for _, c := range []struct {
				host      harness.Sprout
				own, alie string
			}{{s1, m1, m2}, {s2, m2, m1}} {
				osc.Step("each marker landed on its own tenant's machine only (%s)", c.host.VM)
				res, err := f.OnHost(ctx, c.host, harness.MultiFileState([]string{c.own, c.alie}))
				osc.NoErr(err, "vmctl.sh run on %s", c.host.VM)
				ex, err := harness.ParseMultiFileState(res, 2)
				osc.NoErr(err, "reading the file check")
				if !ex[0] {
					osc.Errorf("%s lacks its own tenant's marker %s", c.host.VM, c.own)
				}
				if ex[1] {
					osc.Errorf("%s has the other tenant's marker %s: one tenant's job ran on the other's machine", c.host.VM, c.alie)
				}
			}
		})
	}
	if !ran {
		sc.Skipf("uat.json has no OS with a sprout in both tenants")
	}
}

func TestCoreS3_AssetLinkCodes(t *testing.T) {
	sc := harness.Begin(t, "S3")
	f := ready(t, sc)
	ctx := ctxFor(t, 10*time.Minute)
	t1 := f.Sprouts(harness.InTenant(1))
	if len(t1) < 2 {
		sc.Skipf("needs two sprouts in tenant 1, uat.json has %d", len(t1))
	}
	a, b := t1[0], t1[1]
	for _, s := range []harness.Sprout{a, b} {
		if err := f.Ready(s); err != nil {
			sc.Fatalf("%s not ready: %v", s.VM, err)
		}
	}
	tok := token(t, sc, 1, harness.RoleAdmin)
	tid := f.TenantID(1)
	t.Cleanup(func() { _ = f.EnsureLinked(cleanupCtx(), 1) })

	sc.Step("unlink %s", a.SproutID)
	r, err := f.API.UnlinkAsset(ctx, tok, tid, a.SproutID)
	sc.Expect(r, err, http.StatusOK, "", "DELETE asset-link")
	sc.Step("link it: new")
	r, err = f.API.LinkAsset(ctx, tok, tid, a.SproutID, a.AssetID)
	sc.Expect(r, err, http.StatusCreated, "", "a new link")
	sc.Step("link it again: identical")
	r, err = f.API.LinkAsset(ctx, tok, tid, a.SproutID, a.AssetID)
	sc.Check(r, err, http.StatusOK, "", "repeating an identical link")
	sc.Step("another asset ID for the same sprout")
	r, err = f.API.LinkAsset(ctx, tok, tid, a.SproutID, "uat-s3-other-"+harness.Nonce(6))
	sc.Check(r, err, http.StatusConflict, "asset_link_conflict", "a second asset ID for a linked sprout")
	sc.Step("the same asset ID for another sprout")
	r, err = f.API.LinkAsset(ctx, tok, tid, b.SproutID, a.AssetID)
	sc.Check(r, err, http.StatusConflict, "asset_link_conflict", "a linked asset ID for another sprout")
	for _, c := range f.Sprouts(harness.InTenant(2), harness.WithOS(a.OS)) {
		if c.SproutID == "" {
			continue
		}
		sc.Step("tenant 2 links tenant 1's asset ID to its own %s", c.SproutID)
		r, err = f.API.LinkAsset(ctx, token(t, sc, 2, harness.RoleAdmin), f.TenantID(2), c.SproutID, a.AssetID)
		sc.Check(r, err, http.StatusConflict, "asset_link_conflict", "an asset ID linked in another tenant (asset IDs are global)")
		break
	}
	sc.Step("a sprout the tenant doesn't have")
	r, err = f.API.LinkAsset(ctx, tok, tid, "uat-s3-none-"+harness.Nonce(6), "uat-s3-none-"+harness.Nonce(6))
	sc.Check(r, err, http.StatusNotFound, "sprout_not_found", "linking a sprout that doesn't exist")
	sc.Step("unlink a sprout with no link")
	r, err = f.API.UnlinkAsset(ctx, tok, tid, "uat-s3-none-"+harness.Nonce(6))
	sc.Check(r, err, http.StatusNotFound, "asset_link_not_found", "unlinking a sprout with no link")
}

func TestCoreS4_LookupUnresolvedSilently(t *testing.T) {
	sc := harness.Begin(t, "S4")
	f := ready(t, sc)
	f.EachTenant(t, sc, func(t *testing.T, sc *harness.Scenario, n int) {
		ctx := ctxFor(t, 5*time.Minute)
		tok := token(t, sc, n, harness.RoleAdmin)
		own := harness.Assets(f.Sprouts(harness.InTenant(n)))
		var theirs []string
		for _, s := range f.Sprouts() {
			if s.Tenant != n {
				theirs = append(theirs, s.AssetID)
			}
		}
		none := "uat-s4-none-" + harness.Nonce(8)
		ids := append(append(append([]string{}, own...), theirs...), none)

		sc.Step("look up own, other tenant's and unknown asset IDs")
		lk, r, err := f.API.LookupAssets(ctx, tok, f.TenantID(n), ids)
		sc.Expect(r, err, http.StatusOK, "", "lookup")
		for _, a := range own {
			if _, ok := lk.Find(a); !ok {
				sc.Errorf("own asset %s didn't resolve", a)
			}
		}
		for _, a := range append(theirs, none) {
			if !lk.IsUnresolved(a) {
				sc.Errorf("asset %s isn't in unresolved", a)
			}
		}
		if len(lk.Results) != len(own) {
			sc.Errorf("%d results, want %d (own only)", len(lk.Results), len(own))
		}
		sc.Step("the answer says nothing about why")
		var raw map[string]any
		sc.NoErr(r.Decode(&raw), "decoding")
		for k := range raw {
			if k != "results" && k != "unresolved" {
				sc.Errorf("the lookup carries %q", k)
			}
		}
		if us, ok := raw["unresolved"].([]any); ok {
			for _, u := range us {
				if _, isString := u.(string); !isString {
					sc.Errorf("an unresolved entry is %T, not a bare asset ID", u)
				}
			}
		}

		sc.Step("101 asset IDs")
		many := make([]string, 101)
		for i := range many {
			many[i] = "uat-s4-many-" + harness.Nonce(6)
		}
		_, r, err = f.API.LookupAssets(ctx, tok, f.TenantID(n), many)
		if sc.Check(r, err, http.StatusBadRequest, "too_many_asset_ids", "101 asset IDs") {
			if max, _ := r.Error.Details["max"].(float64); max != 100 {
				sc.Errorf("details.max %v, want 100", r.Error.Details["max"])
			}
		}
		sc.Step("no asset_ids")
		r, err = f.API.Do(ctx, harness.Request{Method: http.MethodGet, Path: harness.TenantPath(f.TenantID(n), "sprouts"), Token: tok})
		sc.Check(r, err, http.StatusBadRequest, "invalid_request", "a lookup without asset_ids")
	})
}

func TestCoreS5_KeylessSproutRefused(t *testing.T) {
	sc := harness.Begin(t, "S5")
	ctx := ctxFor(t, 15*time.Minute)
	key := mintKey(t, sc, 1, 1, 1)
	sc.Step("enrol a synthetic sprout, step 1 only (no box key on record)")
	_, res := syntheticEnroll(t, sc, key.RegistrationKey)
	if !res.OK() {
		sc.Fatalf("enrolment: %s", res)
	}
	asset := linkSynthetic(t, sc, 1, res.SproutID)
	sp := harness.Sprout{VM: "synthetic", Tenant: 1, AssetID: asset}

	sc.Step("cmd.run on it")
	b, err := fleet.DoAssets(ctx, 1, []string{asset}, harness.CmdRunAction(harness.CmdRun{Cmd: "id -u"}), harness.DefaultBatchTimeout)
	sc.NoErr(err, "the cmd.run batch")
	sc.ExpectItem(b, sp, harness.ItemFailed, "sprout_reenroll_required")
	sc.Step("cook on it")
	b, err = fleet.DoAssets(ctx, 1, []string{asset}, harness.CookAction("uat.s5.none", false), harness.DefaultCookTimeout)
	sc.NoErr(err, "the cook batch")
	sc.ExpectItem(b, sp, harness.ItemFailed, "sprout_reenroll_required")
	// "Nothing is sent in plaintext": sprout_reenroll_required is the code
	// farmer answers before sealing or sending anything (FIX.1,
	// internal/cook/reenroll.go); there is no plaintext path left to send
	// on. The bus itself can't be watched from the runner, so this is
	// asserted by the code, not by observing the wire.
}

func TestCoreS6_ReinstallSameHost(t *testing.T) {
	sc := harness.Begin(t, "S6")
	f := ready(t, sc)
	f.EachSprout(t, sc, f.Sprouts(harness.InTenant(1)), func(t *testing.T, sc *harness.Scenario, sp harness.Sprout) {
		if sp.IsWindows() {
			// The MSI comes from the NuGet feed through the Ansible role
			// (win_package), which this suite doesn't drive; reinstalling it
			// by hand needs the package source the role resolved.
			sc.Skipf("reinstalling the MSI needs the source the imas_sprout role resolves from the NuGet feed; not driven from the tests")
		}
		ctx := ctxFor(t, 30*time.Minute)
		sc.Step("uninstall and reinstall the same package version, keeping the config file")
		res, err := f.OnHost(ctx, sp, harness.HostScript{Linux: reinstallScript})
		sc.NoErr(err, "vmctl.sh run")
		if res.ExitCode != 0 {
			sc.Fatalf("the reinstall script exited %d: %s", res.ExitCode, res.Output)
		}
		if v, _ := res.Value("AFTER_REMOVE"); v != "inactive" {
			sc.Errorf("the sprout service was %q after the package was removed", v)
		}
		oldV, _ := res.Value("OLD_VERSION")
		newV, _ := res.Value("NEW_VERSION")
		if oldV == "" || oldV != newV {
			sc.Errorf("version before %q, after %q", oldV, newV)
		}
		sc.Step("it comes back and runs a job")
		sc.NoErr(f.WaitRuns(ctx, []harness.Sprout{sp}, harness.DefaultConnectTimeout), "after the reinstall")
		claims, err := f.HostClaims(ctx, sp)
		sc.NoErr(err, "reading the gateway JWT's claims")
		if got := harness.ClaimString(claims, "sprout_id"); got != sp.SproutID {
			sc.Errorf("sprout_id after the reinstall %q, want %q", got, sp.SproutID)
		}
		if got := harness.ClaimString(claims, "tenant_id"); got != f.TenantID(sp.Tenant) {
			sc.Errorf("tenant_id after the reinstall %q", got)
		}
	})
	t.Run("purge_and_reenrol", func(t *testing.T) {
		// A purge that also deletes /etc/imas/pki gives the host a new NKey,
		// so it enrols as <sprout_id>_1 beside its old record (internal/pki
		// resolveEnrollSproutID). Freeing the old ID needs the sprout
		// deleted first, and saasapi has no route to delete or revoke a
		// sprout (an API gap recorded in the PR); the imas CLI that can
		// (imas keys delete) reaches farmer over the bus, which the runner
		// can't.
		harness.Begin(t, "S6").Skipf("a clean re-enrolment after a purge needs the old sprout deleted, and saasapi has no route to delete or revoke a sprout (API gap)")
	})
}

// reinstallScript removes imas-sprout and installs the same version from
// the repository the role configured, restoring the sprout's config file
// (rpm saves a modified one as .rpmsave on removal). The sprout's
// identity under /etc/imas/pki is runtime state no package owns, so it
// stays, and the sprout comes back under the same ID.
const reinstallScript = `cfg=/etc/imas/sprout
bak=/var/tmp/imas-uat-s6-sprout.conf
cp -p "$cfg" "$bak" || exit 10
if command -v apt-get >/dev/null 2>&1; then
  v=$(dpkg-query -W -f='${Version}' imas-sprout) || exit 11
  echo "__IMAS_UAT_OLD_VERSION=$v"
  DEBIAN_FRONTEND=noninteractive apt-get remove -y imas-sprout >/dev/null 2>&1 || exit 12
  if systemctl is-active --quiet imas-sprout; then echo "__IMAS_UAT_AFTER_REMOVE=active"; else echo "__IMAS_UAT_AFTER_REMOVE=inactive"; fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y -o Dpkg::Options::=--force-confold "imas-sprout=$v" >/dev/null 2>&1 || exit 13
  echo "__IMAS_UAT_NEW_VERSION=$(dpkg-query -W -f='${Version}' imas-sprout)"
else
  v=$(rpm -q --qf '%{VERSION}-%{RELEASE}' imas-sprout) || exit 11
  echo "__IMAS_UAT_OLD_VERSION=$v"
  dnf remove -y imas-sprout >/dev/null 2>&1 || exit 12
  if systemctl is-active --quiet imas-sprout; then echo "__IMAS_UAT_AFTER_REMOVE=active"; else echo "__IMAS_UAT_AFTER_REMOVE=inactive"; fi
  dnf install -y "imas-sprout-$v" >/dev/null 2>&1 || exit 13
  echo "__IMAS_UAT_NEW_VERSION=$(rpm -q --qf '%{VERSION}-%{RELEASE}' imas-sprout)"
fi
cp -p "$bak" "$cfg" || exit 14
systemctl enable imas-sprout >/dev/null 2>&1
systemctl restart imas-sprout || exit 15`
