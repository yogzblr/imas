package shell

import (
	"bufio"
	"bytes"
	"os"
	"slices"
	"strings"
	"sync"
)

// SproutPolicy is the sprout's local say over shells, checked before
// anything is spawned and independent of farmer.
type SproutPolicy struct {
	// Disabled refuses every start (sprout config "disableshell",
	// default false; the Ansible role's imas_sprout_disable_shell).
	Disabled bool
	// AllowedShells is the allow-list (sprout config "shellallowlist").
	// Empty: the shells listed in /etc/shells, read at each start.
	AllowedShells []string
	// MaxSessions caps concurrent sessions (sprout config
	// "shellmaxsessions"); 0 or less is DefaultSproutMaxSessions.
	MaxSessions int
}

var (
	policyMu sync.RWMutex
	policy   = SproutPolicy{}
	// etcShells is EtcShells, swappable in tests.
	etcShells = EtcShells
)

// SetSproutPolicy sets this sprout's policy (cmd/sprout, from its config).
func SetSproutPolicy(p SproutPolicy) {
	policyMu.Lock()
	defer policyMu.Unlock()
	p.AllowedShells = slices.Clone(p.AllowedShells)
	policy = p
}

// CurrentSproutPolicy returns the policy in force.
func CurrentSproutPolicy() SproutPolicy {
	policyMu.RLock()
	defer policyMu.RUnlock()
	p := policy
	p.AllowedShells = slices.Clone(p.AllowedShells)
	return p
}

func (p SproutPolicy) maxSessions() int {
	if p.MaxSessions <= 0 {
		return DefaultSproutMaxSessions
	}
	return p.MaxSessions
}

// allowedShells is the allow-list in force: the configured one, else
// /etc/shells. Only absolute paths count. An unreadable /etc/shells
// allows nothing (fail closed).
func (p SproutPolicy) allowedShells() []string {
	if len(p.AllowedShells) > 0 {
		return absolutePaths(p.AllowedShells)
	}
	data, err := os.ReadFile(etcShells)
	if err != nil {
		return nil
	}
	return parseEtcShells(data)
}

// parseEtcShells reads /etc/shells: one path per line, '#' comments.
func parseEtcShells(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		out = append(out, strings.TrimSpace(line))
	}
	return absolutePaths(out)
}

func absolutePaths(in []string) []string {
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && ValidShellPath(s) {
			out = append(out, s)
		}
	}
	return out
}

// pickShell decides which shell a start that asked for requested runs:
// requested itself if allowed; for an empty request, DefaultShell if
// allowed, else the first allowed shell. ok is false if none qualifies.
func pickShell(requested string, allowed []string) (string, bool) {
	if requested != "" {
		return requested, ValidShellPath(requested) && slices.Contains(allowed, requested)
	}
	if slices.Contains(allowed, DefaultShell) {
		return DefaultShell, true
	}
	if len(allowed) > 0 {
		return allowed[0], true
	}
	return "", false
}
