//go:build systemd_integration

package ingredients

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	_ "github.com/yogzblr/imas/internal/ingredients/service/systemd"
	"github.com/yogzblr/imas/uat/tests/harness"
)

// systemdCases are the service cases, against real systemd: UAT Run 2 on
// rc.21 failed masked and unmasked on AlmaLinux 9 (systemd 252) and passed
// them on Ubuntu and the rig.
var systemdCases = []string{
	"I.service.enabled", "I.service.disabled", "I.service.masked", "I.service.unmasked",
	"I.service.running", "I.service.stopped", "I.service.restarted", "I.service.reloaded",
}

func TestSystemdServiceCases(t *testing.T) {
	runLocalCases(t, systemdCases)
}

// A static unit (no [Install] section): every state read works on it, and
// a change that systemd refuses for it fails rather than hanging.
func TestSystemdStaticUnit(t *testing.T) {
	unit := "imas-it-static-" + strings.ToLower(harness.Nonce(6)) + ".service"
	path := "/usr/local/lib/systemd/system/" + unit
	if err := os.MkdirAll("/usr/local/lib/systemd/system", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[Unit]\nDescription=imas integration static unit\n[Service]\nType=simple\nExecStart=/bin/sleep infinity\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	systemctl := func(args ...string) string {
		out, _ := exec.Command("systemctl", args...).CombinedOutput()
		return strings.TrimSpace(string(out))
	}
	t.Cleanup(func() {
		systemctl("stop", unit)
		systemctl("unmask", unit)
		_ = os.Remove(path)
		systemctl("daemon-reload")
	})
	systemctl("daemon-reload")
	if st := systemctl("is-enabled", unit); st != "static" {
		t.Fatalf("systemctl is-enabled %s: %q, want static", unit, st)
	}
	for _, method := range []string{"enabled", "disabled", "masked", "unmasked", "running", "stopped"} {
		c, err := ingredients.NewRecipeCooker(cook.StepID("static "+method), "service", method, map[string]interface{}{"name": unit})
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		start := time.Now()
		res, err := c.Test(ctx)
		cancel()
		if err != nil || res.Failed {
			t.Errorf("service.%s test mode on a static unit: %v (failed %v, notes %s)", method, err, res.Failed, notes(res))
		}
		if took := time.Since(start); took > 30*time.Second {
			t.Errorf("service.%s test mode on a static unit took %s", method, took)
		}
	}
	c, err := ingredients.NewRecipeCooker("static running", "service", "running", map[string]interface{}{"name": unit})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := c.Apply(context.Background()); err != nil || !res.Changed {
		t.Errorf("service.running on a static unit: %v, changed %v", err, res.Changed)
	}
	if st := systemctl("is-active", unit); st != "active" {
		t.Errorf("after service.running: %s is %q", unit, st)
	}
}
