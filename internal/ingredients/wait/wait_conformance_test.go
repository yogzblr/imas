package wait

import (
	"reflect"
	"testing"
)

// UAT.9: wait.poll ran every command through `sh -c`, which Windows doesn't
// have, so on a Windows sprout the poll could never succeed (uat/cases/wait/poll.yaml).
func TestPollShellByOS(t *testing.T) {
	exe, args := shellFor("linux", "test -d /var/tmp")
	if exe != "sh" || !reflect.DeepEqual(args, []string{"-c", "test -d /var/tmp"}) {
		t.Errorf("linux: %s %v", exe, args)
	}
	for _, goos := range []string{"windows"} {
		exe, args = shellFor(goos, "hostname")
		if exe == "sh" || exe != "powershell.exe" || !reflect.DeepEqual(args, []string{"-NoProfile", "-NonInteractive", "-Command", "hostname"}) {
			t.Errorf("%s: %s %v, want powershell.exe -NoProfile -NonInteractive -Command <cmd>", goos, exe, args)
		}
	}
}
