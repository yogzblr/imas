//go:build windows

// Package winupdate implements imas's win_update ingredient: searching
// for and installing Windows Update Agent (WUA) updates, matching the
// relevant surface of Salt's win_wua module. It drives the WUA COM API
// (Microsoft.Update.Session -> IUpdateSession/IUpdateSearcher/
// IUpdateDownloader/IUpdateInstaller) the same way Salt's Python
// implementation drives it through win32com.client.Dispatch. See G.6
// in docs/design/imas-windows-parity-addendum.md; the COM lifecycle
// pattern (locked OS thread, single-threaded apartment, explicit
// Release of every acquired IDispatch) follows the one the
// winshortcut ingredient established.
//
// FLAG FOR SECURITY REVIEW: this package cross-compiles (GOOS=windows)
// cleanly but has not been exercised against a real Windows Update
// Agent; treat it as ready for review, not verified. Three things are
// worth a deliberate look beyond the general "written, not verified"
// caveat every G.6 ingredient carries: (1) installing an update is not
// easily reversible and can force a reboot -- the "installed" method
// only ever acts on the KB IDs a recipe explicitly lists in kb_ids,
// never on a blanket "install everything found" criteria, specifically
// to keep a misconfigured recipe's blast radius bounded; see install.go.
// (2) the same VARIANT/IDispatch over-release trap documented in
// wintaskscheduler/com.go applies here too. (3) unlike Task Scheduler's
// action/trigger collections (1-based), WUA's IUpdateCollection and
// IStringCollection are 0-based -- see collectUpdateInfo in com.go.
//
// Deliberately left out of this first pass: per-update install result
// codes (IInstallationResult.GetUpdateResult(i).ResultCode) -- Install
// in com.go only reads the aggregate RebootRequired flag, so a partial
// failure across several queued updates is not currently surfaced
// per-update, only as an overall error from the Install COM call
// itself (which fires for a full-batch failure, not necessarily a
// partial one).
package winupdate

import (
	"context"
	"errors"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_update"

const methodInstalled = "installed"

var (
	ErrUpdateMethodUndefined = errors.New("winupdate method undefined")
	ErrMissingKBIDs          = errors.New("winupdate installed requires at least one kb_ids entry")
)

// Compile-time interface check.
var _ cook.RecipeCooker = Update{}

// Update is a imas ingredient for installing Windows Update Agent
// updates by KB article ID.
type Update struct {
	id     string
	method string
	params map[string]interface{}
}

func (u Update) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	parsed := Update{id: id, method: method, params: params}
	if err := parsed.validate(); err != nil {
		return nil, err
	}
	return parsed, nil
}

func (u Update) validate() error {
	if u.method != methodInstalled {
		return errors.Join(ErrUpdateMethodUndefined, fmt.Errorf("method %s undefined", u.method))
	}
	kbIDs, ok := winexec.StringSliceParam(u.params, "kb_ids")
	if !ok || len(kbIDs) == 0 {
		return ErrMissingKBIDs
	}
	return nil
}

func (u Update) dispatch(ctx context.Context, test bool) (cook.Result, error) {
	switch u.method {
	case methodInstalled:
		return u.installed(ctx, test)
	default:
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil},
			errors.Join(ErrUpdateMethodUndefined, fmt.Errorf("method %s undefined", u.method))
	}
}

func (u Update) Test(ctx context.Context) (cook.Result, error) {
	return u.dispatch(ctx, true)
}

func (u Update) Apply(ctx context.Context) (cook.Result, error) {
	return u.dispatch(ctx, false)
}

func (u Update) PropertiesForMethod(method string) (map[string]string, error) {
	switch method {
	case methodInstalled:
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "kb_ids", Type: "[]string", IsReq: true, Description: "KB article IDs (e.g. KB5001330) to ensure are installed"},
			ingredients.MethodProps{Key: "search_criteria", Type: "string", IsReq: false, Description: "WUA search criteria override (default: not-installed, non-hidden software updates)"},
			ingredients.MethodProps{Key: "accept_eula", Type: "bool", IsReq: false, Description: "auto-accept a matched update's EULA (default true); false skips updates pending EULA acceptance instead of installing them"},
		}.ToMap(), nil
	default:
		return nil, errors.Join(ErrUpdateMethodUndefined, fmt.Errorf("method %s undefined", method))
	}
}

func (u Update) Methods() (string, []string) {
	return ingredientName, []string{methodInstalled}
}

func (u Update) Properties() (map[string]interface{}, error) {
	return u.params, nil
}

func init() {
	ingredients.RegisterAllMethods(Update{})
}
