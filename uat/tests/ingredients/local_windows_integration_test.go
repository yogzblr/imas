//go:build windows_integration

package ingredients

import (
	"testing"

	// The ingredients a Windows sprout registers that the cases below cook
	// (cmd/sprout/include*.go).
	_ "github.com/yogzblr/imas/internal/ingredients/group"
	_ "github.com/yogzblr/imas/internal/ingredients/registry"
	_ "github.com/yogzblr/imas/internal/ingredients/service/windows"
	_ "github.com/yogzblr/imas/internal/ingredients/user"
	_ "github.com/yogzblr/imas/internal/ingredients/wincertutil"
	_ "github.com/yogzblr/imas/internal/ingredients/windacl"
	_ "github.com/yogzblr/imas/internal/ingredients/windsc"
	_ "github.com/yogzblr/imas/internal/ingredients/winfirewall"
	_ "github.com/yogzblr/imas/internal/ingredients/winpsget"
	_ "github.com/yogzblr/imas/internal/ingredients/winshortcut"
	_ "github.com/yogzblr/imas/internal/ingredients/wintaskscheduler"
)

// windowsCases are the Windows ingredient cases UAT Run 2 on rc.21 failed
// or that share their code paths, run here against the OS: netsh, Task
// Scheduler COM, the ACL API, certutil, PowerShellGet (from PSGallery),
// the shortcut child process, local users and groups, the SCM, the
// registry, and DSC's LCM over a DCOM CIM session.
var windowsCases = []string{
	"I.win_firewall.rule_present", "I.win_firewall.rule_absent",
	"I.win_task.present", "I.win_task.absent",
	"I.win_dacl.ace_present", "I.win_dacl.ace_absent",
	"I.win_certutil.cert_present", "I.win_certutil.cert_absent",
	"I.win_psget.installed", "I.win_psget.removed",
	"I.win_shortcut.present", "I.win_shortcut.absent",
	"I.user.present", "I.user.absent", "I.user.exists",
	"I.group.present", "I.group.absent", "I.group.exists",
	"I.service.running", "I.service.stopped", "I.service.restarted",
	"I.service.enabled", "I.service.disabled", "I.service.masked", "I.service.unmasked",
	"I.registry.present", "I.registry.absent", "I.registry.key_present", "I.registry.key_absent",
	"I.win_dsc.applied",
}

func TestWindowsIngredientsOnTheOS(t *testing.T) {
	runLocalCases(t, windowsCases)
}
