package cron

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// identifierPrefix marks the comment line imas writes immediately above a
// managed cron entry, so the entry can be found and updated/removed later
// without depending on the schedule or command staying the same.
const identifierPrefix = "# IMAS_CRON_ID:"

// Entry is a single crontab schedule line.
type Entry struct {
	Minute, Hour, DayOfMonth, Month, DayOfWeek string
	Command                                    string
}

// Line is one line of a crontab: either a parsed Entry (optionally tagged
// with an Identifier from a preceding imas marker comment), or a
// comment/blank/env-var line preserved verbatim.
type Line struct {
	Raw        string
	Entry      *Entry
	Identifier string
}

// ParseCrontab parses crontab-format text, preserving comments, blank
// lines, and env-var assignments (e.g. "MAILTO=root") verbatim so a
// rewrite only touches the lines it manages.
func ParseCrontab(r io.Reader) ([]Line, error) {
	var lines []Line
	pendingID := ""
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)

		if strings.HasPrefix(trimmed, identifierPrefix) {
			// Not appended as its own Line: WriteCrontab regenerates this
			// marker from the following entry's Identifier field, so
			// keeping it here too would duplicate it on a round-trip.
			pendingID = strings.TrimSpace(strings.TrimPrefix(trimmed, identifierPrefix))
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || isEnvAssignment(trimmed) {
			lines = append(lines, Line{Raw: raw})
			pendingID = ""
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 6 {
			// Not a recognisable schedule line; preserve as-is.
			lines = append(lines, Line{Raw: raw})
			pendingID = ""
			continue
		}
		entry := &Entry{
			Minute: fields[0], Hour: fields[1], DayOfMonth: fields[2],
			Month: fields[3], DayOfWeek: fields[4],
			Command: strings.Join(fields[5:], " "),
		}
		lines = append(lines, Line{Entry: entry, Identifier: pendingID})
		pendingID = ""
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// isEnvAssignment reports whether a crontab line looks like a
// "NAME=value" env-var assignment rather than a schedule line.
func isEnvAssignment(trimmed string) bool {
	eq := strings.Index(trimmed, "=")
	if eq <= 0 {
		return false
	}
	name := trimmed[:eq]
	for i, r := range name {
		if r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') ||
			(i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

// FormatEntry renders an Entry as a single crontab-format line (no
// trailing newline).
func FormatEntry(e Entry) string {
	return fmt.Sprintf("%s %s %s %s %s %s", e.Minute, e.Hour, e.DayOfMonth, e.Month, e.DayOfWeek, e.Command)
}

// WriteCrontab writes lines back out, one per line, re-emitting the
// identifier marker comment above any tagged entry.
func WriteCrontab(w io.Writer, lines []Line) error {
	bw := bufio.NewWriter(w)
	for _, l := range lines {
		if l.Entry != nil {
			if l.Identifier != "" {
				if _, err := fmt.Fprintln(bw, identifierPrefix+l.Identifier); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintln(bw, FormatEntry(*l.Entry)); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintln(bw, l.Raw); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// FindByIdentifier returns the index of the entry line tagged with the
// given identifier, or -1 if none is tagged with it.
func FindByIdentifier(lines []Line, identifier string) int {
	for i, l := range lines {
		if l.Entry != nil && l.Identifier == identifier {
			return i
		}
	}
	return -1
}

// FindByCommand returns the index of the first untagged entry whose
// command matches exactly, or -1 if none does.
func FindByCommand(lines []Line, command string) int {
	for i, l := range lines {
		if l.Entry != nil && l.Entry.Command == command {
			return i
		}
	}
	return -1
}

func entriesEqual(a, b Entry) bool {
	return a == b
}

// UpsertEntry adds or updates the (optionally identifier-tagged) entry.
// Lookup prefers a matching identifier; when identifier is empty, it
// matches by exact command text instead. Returns the updated lines and
// whether anything changed.
func UpsertEntry(lines []Line, identifier string, newEntry Entry) ([]Line, bool) {
	idx := -1
	if identifier != "" {
		idx = FindByIdentifier(lines, identifier)
	} else {
		idx = FindByCommand(lines, newEntry.Command)
	}
	if idx >= 0 {
		if entriesEqual(*lines[idx].Entry, newEntry) {
			return lines, false
		}
		out := make([]Line, len(lines))
		copy(out, lines)
		out[idx] = Line{Entry: &newEntry, Identifier: identifier}
		return out, true
	}
	out := make([]Line, len(lines), len(lines)+1)
	copy(out, lines)
	out = append(out, Line{Entry: &newEntry, Identifier: identifier})
	return out, true
}

// RemoveEntry removes the (optionally identifier-tagged) matching entry,
// along with its marker comment. Returns the updated lines and whether
// anything was removed.
func RemoveEntry(lines []Line, identifier, command string) ([]Line, bool) {
	idx := -1
	if identifier != "" {
		idx = FindByIdentifier(lines, identifier)
	}
	if idx < 0 && command != "" {
		idx = FindByCommand(lines, command)
	}
	if idx < 0 {
		return lines, false
	}
	out := make([]Line, 0, len(lines)-1)
	out = append(out, lines[:idx]...)
	out = append(out, lines[idx+1:]...)
	return out, true
}
