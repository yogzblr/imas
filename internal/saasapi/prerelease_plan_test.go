package saasapi

// A prerelease is never installed on Windows (owner's decision on PR #86):
// planning fails a Windows sprout of a prerelease rollout up front with
// no_release_for_platform, unsent. Linux sprouts and release versions are
// planned as before. FLAG FOR SECURITY REVIEW.

import (
	"context"
	"testing"
)

type staticFacts map[SproutRef]SproutFacts

func (f staticFacts) SproutFacts(_ context.Context, tenantID string, ids []string) (map[SproutRef]SproutFacts, error) {
	out := map[SproutRef]SproutFacts{}
	for _, id := range ids {
		ref := SproutRef{TenantID: tenantID, SproutID: id}
		if v, ok := f[ref]; ok {
			out[ref] = v
		}
	}
	return out, nil
}

func (f staticFacts) SproutFactsWithWriteTimes(context.Context, string, []string) (map[SproutRef]TimedSproutFacts, error) {
	return nil, nil
}

func TestPlanUpdateItems_PrereleaseNotForWindows(t *testing.T) {
	const tid = "t_plan"
	facts := staticFacts{
		{TenantID: tid, SproutID: "lin"}:     {OS: "linux", Arch: "amd64", Version: "v2.4.0"},
		{TenantID: tid, SproutID: "win"}:     {OS: "windows", Arch: "amd64", Version: "v2.4.0"},
		{TenantID: tid, SproutID: "unknown"}: {},
	}
	rows := []sproutByAssetItem{
		{SproutID: "lin", AssetID: "a1", KeyState: keyStateAccepted},
		{SproutID: "win", AssetID: "a2", KeyState: keyStateAccepted},
		{SproutID: "unknown", AssetID: "a3", KeyState: keyStateAccepted},
	}
	catalog := func(version string) []FleetVersion {
		return []FleetVersion{
			{Version: version, OS: "linux", Arch: "amd64", PackageType: "deb", MinSproutVersion: "v2.0.0"},
			{Version: version, OS: "linux", Arch: "amd64", PackageType: "rpm", MinSproutVersion: "v2.0.0"},
			{Version: version, OS: "windows", Arch: "amd64", PackageType: "msi", MinSproutVersion: "v2.0.0"},
		}
	}
	for _, tc := range []struct {
		version string
		win     string
	}{
		{"v2.5.0-rc.1", errCodeNoReleaseForPlatform},
		{"v2.5.0", ""},
	} {
		blocked, _, err := planUpdateItems(context.Background(), facts, tid, rows, catalog(tc.version))
		if err != nil {
			t.Fatal(err)
		}
		if got := blocked[SproutRef{TenantID: tid, SproutID: "win"}]; got != tc.win {
			t.Errorf("%s: windows sprout blocked with %q, want %q", tc.version, got, tc.win)
		}
		for _, id := range []string{"lin", "unknown"} {
			if got := blocked[SproutRef{TenantID: tid, SproutID: id}]; got != "" {
				t.Errorf("%s: %s blocked with %q", tc.version, id, got)
			}
		}
	}
}
