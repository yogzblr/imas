package winshortcut

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

// runPowerShellEnv runs powershell.exe with extra environment; tests
// replace it.
var runPowerShellEnv = winexec.RunPowerShellEnv

// childTimeout bounds one child powershell.exe: starting it and the shell
// object takes a second or two; a child that runs longer is stuck and is
// killed.
var childTimeout = 60 * time.Second

// inputEnv carries the request into the child as base64 JSON, so no path
// or property a recipe supplies is ever part of the script text.
const inputEnv = "IMAS_SHORTCUT_REQUEST"

// scriptPrologue decodes the request and opens the shortcut. Output is
// UTF-8 JSON on stdout (powershell.exe otherwise writes the OEM code
// page, which mangles non-ASCII paths); failures stop the script with a
// non-zero exit and the reason on stderr.
const scriptPrologue = `$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$req = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:` + inputEnv + `)) | ConvertFrom-Json
$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut($req.Path)
`

// loadScript prints the shortcut's properties as JSON.
const loadScript = scriptPrologue + `[pscustomobject]@{
  TargetPath = [string]$lnk.TargetPath
  Arguments = [string]$lnk.Arguments
  Description = [string]$lnk.Description
  WorkingDirectory = [string]$lnk.WorkingDirectory
  IconLocation = [string]$lnk.IconLocation
  WindowStyle = [int]$lnk.WindowStyle
  Hotkey = [string]$lnk.Hotkey
} | ConvertTo-Json -Compress
`

// saveScript sets the properties from the request and saves the file.
const saveScript = scriptPrologue + `$s = $req.State
$lnk.TargetPath = [string]$s.TargetPath
$lnk.Arguments = [string]$s.Arguments
$lnk.Description = [string]$s.Description
$lnk.WorkingDirectory = [string]$s.WorkingDirectory
if ([string]$s.IconLocation -ne '') { $lnk.IconLocation = [string]$s.IconLocation }
$lnk.Hotkey = [string]$s.Hotkey
$lnk.WindowStyle = [int]$s.WindowStyle
$lnk.Save()
`

// psShortcutBackend implements shortcutBackend with WScript.Shell in a
// child powershell.exe (see the package doc for why not in-process).
type psShortcutBackend struct{}

type shortcutRequest struct {
	Path  string         `json:"Path"`
	State *shortcutState `json:"State,omitempty"`
}

// requestEnv is the child's environment entry for req.
func requestEnv(req shortcutRequest) (string, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	return inputEnv + "=" + base64.StdEncoding.EncodeToString(b), nil
}

// runShortcutChild runs one of the child scripts for req, bounded by
// childTimeout and by ctx. A child that dies of a native fault (an NTSTATUS
// exit code, 0xC0000005 and the like) is named as such.
func runShortcutChild(ctx context.Context, op, script string, req shortcutRequest) (string, error) {
	env, err := requestEnv(req)
	if err != nil {
		return "", fmt.Errorf("winshortcut: %s(%q): %w", op, req.Path, err)
	}
	out, err := runPowerShellEnv(ctx, script, []string{env}, childTimeout)
	if err != nil {
		if code, ok := winexec.ExitCode(err); ok && uint32(code) >= 0xC0000000 {
			return out, fmt.Errorf("winshortcut: %s(%q): the shell automation child faulted (exit 0x%08X); the sprout is unaffected: %w", op, req.Path, uint32(code), err)
		}
		return out, fmt.Errorf("winshortcut: %s(%q) in a child powershell.exe: %w", op, req.Path, err)
	}
	return out, nil
}

// Load reads the shortcut at path through the child.
func (psShortcutBackend) Load(ctx context.Context, path string) (shortcutState, error) {
	out, err := runShortcutChild(ctx, "Load", loadScript, shortcutRequest{Path: path})
	if err != nil {
		return shortcutState{}, err
	}
	var state shortcutState
	// Setting the console to UTF-8 can make powershell.exe write a BOM first.
	if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(out), "\uFEFF")), &state); err != nil {
		return shortcutState{}, fmt.Errorf("winshortcut: Load(%q): parsing the child's output: %w (output: %s)", path, err, out)
	}
	return state, nil
}

// Save writes state to the shortcut at path through the child.
func (psShortcutBackend) Save(ctx context.Context, path string, state shortcutState) error {
	_, err := runShortcutChild(ctx, "Save", saveScript, shortcutRequest{Path: path, State: &state})
	return err
}
