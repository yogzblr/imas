package cron

import (
	"bytes"
	"strings"
	"testing"
)

const sampleCrontab = `# comment
MAILTO=root

0 3 * * * /usr/bin/backup.sh
# IMAS_CRON_ID:cleanup
15 4 * * * /usr/bin/cleanup.sh --quiet
`

func TestParseCrontab(t *testing.T) {
	lines, err := ParseCrontab(strings.NewReader(sampleCrontab))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var entries []Line
	for _, l := range lines {
		if l.Entry != nil {
			entries = append(entries, l)
		}
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Identifier != "" {
		t.Errorf("expected first entry to be untagged, got %q", entries[0].Identifier)
	}
	if entries[0].Entry.Command != "/usr/bin/backup.sh" {
		t.Errorf("unexpected command: %q", entries[0].Entry.Command)
	}
	if entries[1].Identifier != "cleanup" {
		t.Errorf("expected identifier 'cleanup', got %q", entries[1].Identifier)
	}
	if entries[1].Entry.Command != "/usr/bin/cleanup.sh --quiet" {
		t.Errorf("unexpected command: %q", entries[1].Entry.Command)
	}
	if entries[1].Entry.Hour != "4" || entries[1].Entry.Minute != "15" {
		t.Errorf("unexpected schedule: %+v", entries[1].Entry)
	}
}

func TestParseCrontabPreservesCommentsAndEnv(t *testing.T) {
	lines, err := ParseCrontab(strings.NewReader(sampleCrontab))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	foundComment, foundEnv := false, false
	for _, l := range lines {
		if l.Entry == nil && l.Raw == "# comment" {
			foundComment = true
		}
		if l.Entry == nil && l.Raw == "MAILTO=root" {
			foundEnv = true
		}
	}
	if !foundComment || !foundEnv {
		t.Fatalf("expected comment and env lines preserved, got %+v", lines)
	}
}

func TestWriteCrontabRoundTrip(t *testing.T) {
	lines, err := ParseCrontab(strings.NewReader(sampleCrontab))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteCrontab(&buf, lines); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	written := buf.String()
	reparsed, err := ParseCrontab(strings.NewReader(written))
	if err != nil {
		t.Fatalf("unexpected error reparsing: %v", err)
	}
	if len(reparsed) != len(lines) {
		t.Fatalf("expected %d lines, got %d:\n%s", len(lines), len(reparsed), written)
	}
	idx := FindByIdentifier(reparsed, "cleanup")
	if idx < 0 {
		t.Fatal("expected identifier to survive round-trip")
	}
	// The identifier marker must appear exactly once, not duplicated.
	if strings.Count(written, "IMAS_CRON_ID:cleanup") != 1 {
		t.Fatalf("expected identifier marker exactly once, got:\n%s", written)
	}
}

func TestFindByIdentifierAndCommand(t *testing.T) {
	lines, _ := ParseCrontab(strings.NewReader(sampleCrontab))
	if idx := FindByIdentifier(lines, "cleanup"); idx < 0 {
		t.Fatal("expected to find cleanup identifier")
	}
	if idx := FindByIdentifier(lines, "nope"); idx >= 0 {
		t.Fatal("expected -1 for missing identifier")
	}
	if idx := FindByCommand(lines, "/usr/bin/backup.sh"); idx < 0 {
		t.Fatal("expected to find backup command")
	}
	if idx := FindByCommand(lines, "/usr/bin/nope"); idx >= 0 {
		t.Fatal("expected -1 for missing command")
	}
}

func TestUpsertEntryByIdentifierAppend(t *testing.T) {
	lines, _ := ParseCrontab(strings.NewReader(sampleCrontab))
	newEntry := Entry{Minute: "0", Hour: "0", DayOfMonth: "*", Month: "*", DayOfWeek: "*", Command: "/usr/bin/new.sh"}
	updated, changed := UpsertEntry(lines, "new-job", newEntry)
	if !changed {
		t.Fatal("expected changed=true")
	}
	idx := FindByIdentifier(updated, "new-job")
	if idx < 0 || updated[idx].Entry.Command != "/usr/bin/new.sh" {
		t.Fatalf("expected new entry to be appended, got %+v", updated)
	}
}

func TestUpsertEntryByIdentifierUpdate(t *testing.T) {
	lines, _ := ParseCrontab(strings.NewReader(sampleCrontab))
	newEntry := Entry{Minute: "30", Hour: "5", DayOfMonth: "*", Month: "*", DayOfWeek: "*", Command: "/usr/bin/cleanup.sh --quiet"}
	updated, changed := UpsertEntry(lines, "cleanup", newEntry)
	if !changed {
		t.Fatal("expected changed=true when schedule differs")
	}
	idx := FindByIdentifier(updated, "cleanup")
	if idx < 0 || updated[idx].Entry.Minute != "30" {
		t.Fatalf("expected updated schedule, got %+v", updated[idx])
	}
	if len(updated) != len(lines) {
		t.Fatalf("update should not change line count: got %d want %d", len(updated), len(lines))
	}
}

func TestUpsertEntryNoChange(t *testing.T) {
	lines, _ := ParseCrontab(strings.NewReader(sampleCrontab))
	idx := FindByIdentifier(lines, "cleanup")
	updated, changed := UpsertEntry(lines, "cleanup", *lines[idx].Entry)
	if changed {
		t.Fatal("expected changed=false for identical entry")
	}
	if len(updated) != len(lines) {
		t.Fatal("expected unchanged line count")
	}
}

func TestUpsertEntryByCommandWhenNoIdentifier(t *testing.T) {
	lines, _ := ParseCrontab(strings.NewReader(sampleCrontab))
	// No identifier given: match by exact command text instead.
	newEntry := Entry{Minute: "1", Hour: "1", DayOfMonth: "*", Month: "*", DayOfWeek: "*", Command: "/usr/bin/backup.sh"}
	updated, changed := UpsertEntry(lines, "", newEntry)
	if !changed {
		t.Fatal("expected changed=true when schedule differs")
	}
	if len(updated) != len(lines) {
		t.Fatalf("expected in-place update by command match, got %d vs %d lines", len(updated), len(lines))
	}
}

func TestRemoveEntryByIdentifier(t *testing.T) {
	lines, _ := ParseCrontab(strings.NewReader(sampleCrontab))
	updated, removed := RemoveEntry(lines, "cleanup", "")
	if !removed {
		t.Fatal("expected removed=true")
	}
	if FindByIdentifier(updated, "cleanup") >= 0 {
		t.Fatal("expected cleanup entry to be gone")
	}
	if FindByCommand(updated, "/usr/bin/backup.sh") < 0 {
		t.Fatal("expected untouched entry to survive")
	}

	_, removedAgain := RemoveEntry(updated, "cleanup", "")
	if removedAgain {
		t.Fatal("expected removed=false when already gone")
	}
}

func TestRemoveEntryByCommandFallback(t *testing.T) {
	lines, _ := ParseCrontab(strings.NewReader(sampleCrontab))
	updated, removed := RemoveEntry(lines, "unknown-id", "/usr/bin/backup.sh")
	if !removed {
		t.Fatal("expected removed=true via command fallback")
	}
	if FindByCommand(updated, "/usr/bin/backup.sh") >= 0 {
		t.Fatal("expected backup entry to be gone")
	}
}

func TestIsEnvAssignment(t *testing.T) {
	cases := map[string]bool{
		"MAILTO=root":        true,
		"PATH=/bin:/usr/bin": true,
		"0 3 * * * cmd":      false,
		"=nope":              false,
		"# comment":          false,
	}
	for in, want := range cases {
		if got := isEnvAssignment(in); got != want {
			t.Errorf("isEnvAssignment(%q) = %v, want %v", in, got, want)
		}
	}
}
