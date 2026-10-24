//go:build uat

package ingredients

import (
	"context"
	"flag"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

// fleet is the run's harness, built once in TestMain (as in uat/tests).
var fleet *harness.Fleet

func TestMain(m *testing.M) {
	flag.Parse()
	env, err := harness.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "uat ingredients: %v\n", err)
		os.Exit(1)
	}
	fleet, err = harness.NewFleet(env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "uat ingredients: %v\n", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	// UAT.4 binds tenants 1 and 2; check each tenant's token carries its
	// ID before anything runs, as uat/tests does.
	err = fleet.CheckTenantClaims(ctx)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "uat ingredients: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// ready returns the fleet with every sprout's ID resolved and asset ID
// linked, failing the test if that couldn't start at all.
func ready(t *testing.T, sc *harness.Scenario) *harness.Fleet {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	if err := fleet.Prepare(ctx); err != nil {
		sc.Fatalf("preparing the sprouts (sprout IDs, asset links): %v", err)
	}
	return fleet
}

// ctxFor returns a context bounded by d, cancelled when the test ends.
func ctxFor(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// harnessDriver is the Driver of a real run: saasapi for recipes and
// cooks, vmctl.sh for the host, and (W10) the VM's side of a failure
// through diagnostics.sh vm.
type harnessDriver struct {
	f    *harness.Fleet
	diag *harness.VMDiag
}

// longCallTimeout is vmctl.sh's call timeout for a setup or revert script,
// which may install or remove a package (its default is 120 s).
const longCallTimeout = 5 * time.Minute

func (d harnessDriver) Upload(ctx context.Context, tenant int, name, content string) error {
	tok, err := d.f.Admin(ctx, tenant)
	if err != nil {
		return err
	}
	_, err = d.f.API.UploadRecipe(ctx, tok, d.f.TenantID(tenant), name, content)
	return err
}

func (d harnessDriver) Delete(ctx context.Context, tenant int, name string) {
	tok, err := d.f.Admin(ctx, tenant)
	if err != nil {
		return
	}
	for i := 0; i < 5; i++ {
		r, err := d.f.API.DeleteRecipe(ctx, tok, d.f.TenantID(tenant), name)
		if err != nil || r.Status != 429 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (d harnessDriver) Cook(ctx context.Context, sp harness.Sprout, recipe string, test bool, timeout time.Duration) (harness.Item, error) {
	b, err := d.f.DoAssets(ctx, sp.Tenant, []string{sp.AssetID}, harness.CookAction(recipe, test), timeout)
	if err != nil {
		return harness.Item{}, err
	}
	it, ok := b.For(sp)
	if !ok {
		return harness.Item{}, fmt.Errorf("the batch has no item for asset %s", sp.AssetID)
	}
	return it, nil
}

func (d harnessDriver) Run(ctx context.Context, sp harness.Sprout, script string) (*harness.RunResult, error) {
	return d.run(ctx, sp, script, harness.RunOptions{})
}

// RunLong is Run with a longer call timeout (LongRunner).
func (d harnessDriver) RunLong(ctx context.Context, sp harness.Sprout, script string) (*harness.RunResult, error) {
	return d.run(ctx, sp, script, harness.RunOptions{CallTimeout: longCallTimeout})
}

// RunOutOfBand is Run through az vm run-command (OutOfBand).
func (d harnessDriver) RunOutOfBand(ctx context.Context, sp harness.Sprout, script string) (*harness.RunResult, error) {
	return d.f.VM.RunWith(ctx, sp.VM, sp.Family(), script, harness.RunOptions{OutOfBand: true, CallTimeout: longCallTimeout})
}

// run runs a host script; a test channel that failed has the VM's side of
// it collected while it is fresh.
func (d harnessDriver) run(ctx context.Context, sp harness.Sprout, script string, opt harness.RunOptions) (*harness.RunResult, error) {
	res, err := d.f.VM.RunWith(ctx, sp.VM, sp.Family(), script, opt)
	if harness.IsChannelUnavailable(err) {
		d.Diagnose(ctx, sp)
	}
	return res, err
}

// Diagnose collects the VM's side of a failure (Diagnoser).
func (d harnessDriver) Diagnose(ctx context.Context, sp harness.Sprout, jids ...string) string {
	where, err := d.diag.Collect(ctx, sp.VM, jids...)
	if err != nil {
		return where + " (incomplete: " + err.Error() + ")"
	}
	return where
}
