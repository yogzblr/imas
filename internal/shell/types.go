// Package shell is interactive shell sessions over the bus, sealed end to
// end (docs/design/imas-payload-encryption-design.md, "Sealing shell.*";
// J.5). FLAG FOR SECURITY REVIEW.
//
// Farmer relays, with both legs sealed:
//
//	CLI --leg 1 (c2f/f2c)--> farmer --leg 2 (f2s/s2f)--> sprout
//
// Leg 1 starts with a sealed control-plane request, c2f.shell.open on
// imas.api.shell.open, sealed with the user's registered CLI box key to
// the tenant box key the CLI pins; leg 2 with f2s.shell.start on
// imas.sprouts.<id>.shell.start, sealed to the sprout's box key. Each
// handshake carries one ephemeral X25519 key from each end, and after it
// the leg is a payloadbox.Stream: numbered frames under keys derived from
// those ephemeral keys alone. The CLI and the sprout never talk directly,
// and nothing on the bus is plaintext.
//
// This package holds the wire types and subjects both ends share, the
// sprout's side (sprout_unix.go, sprout_windows.go: Sprout), the CLI's side
// (client.go: RunClient) and farmer's session tracker. Farmer's relay is
// internal/natsapi's shell.go.
package shell

import (
	"encoding/hex"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/payloadbox"
)

// Farmer's policy defaults (owner decisions, 2026-10-04).
const (
	// DefaultIdleTimeout is farmer's idle timeout when its config sets
	// none; MaxIdleTimeout is the most it may be set to. The CLI may only
	// ask for something shorter.
	DefaultIdleTimeout = 15 * time.Minute
	MaxIdleTimeout     = 60 * time.Minute
	// MaxSessionDuration is the longest a session may last, and farmer's
	// default.
	MaxSessionDuration = 8 * time.Hour
	// HelloTimeout is how long farmer waits for the CLI's HELLO (key
	// confirmation) after answering its open, before dropping the session
	// without contacting the sprout.
	HelloTimeout = 10 * time.Second
	// StartTimeout bounds farmer's f2s.shell.start request.
	StartTimeout = 10 * time.Second
)

// Sprout policy defaults.
const (
	// DefaultShell is the shell a start that names none gets, if the
	// allow-list has it.
	DefaultShell = "/bin/sh"
	// EtcShells is the allow-list a sprout uses when its config sets none.
	EtcShells = "/etc/shells"
	// DefaultSproutMaxSessions caps concurrent sessions on one sprout.
	DefaultSproutMaxSessions = 8
)

// OpenRequest is the body of the CLI's c2f.shell.open request (the sealed
// params of imas.api.shell.open).
type OpenRequest struct {
	SproutID string `json:"sprout_id"`
	// Shell is the path to run; empty means the sprout's default.
	Shell string `json:"shell,omitempty"`
	// IdleTimeoutSec may only shorten farmer's idle timeout; 0 keeps it.
	IdleTimeoutSec int `json:"idle_timeout_sec,omitempty"`
	// CLIEphPub is the CLI's ephemeral X25519 public key for leg 1.
	CLIEphPub []byte `json:"cli_eph_pub"`
}

// OpenResult is farmer's answer to an OpenRequest, inside its sealed
// reply.
type OpenResult struct {
	SessionID string `json:"session_id"`
	SproutID  string `json:"sprout_id"`
	// FarmerEphPub is farmer's ephemeral X25519 public key for leg 1.
	FarmerEphPub   []byte `json:"farmer_eph_pub"`
	IdleTimeoutSec int    `json:"idle_timeout_sec"`
	MaxDurationSec int    `json:"max_duration_sec"`
}

// StartUser names who opened a session, so the sprout can log it.
type StartUser struct {
	Pubkey string `json:"pubkey"`
	Name   string `json:"name,omitempty"`
}

// StartBody is the body of farmer's f2s.shell.start.
type StartBody struct {
	SessionID string `json:"session_id"`
	// FarmerEphPub is farmer's ephemeral X25519 public key for leg 2.
	FarmerEphPub   []byte    `json:"farmer_eph_pub"`
	Cols           int       `json:"cols"`
	Rows           int       `json:"rows"`
	Shell          string    `json:"shell,omitempty"`
	IdleTimeoutSec int       `json:"idle_timeout_sec"`
	MaxDurationSec int       `json:"max_duration_sec"`
	User           StartUser `json:"user"`
}

// StartReply is the body of the sprout's sealed s2f.shell.start: its
// ephemeral key, or a fixed refusal code (Error) that only farmer can
// read. A failure to open the start uses payloadbox.ErrorHeader instead.
type StartReply struct {
	SproutEphPub []byte `json:"sprout_eph_pub,omitempty"`
	Error        string `json:"error,omitempty"`
}

// The sprout's refusal codes, in StartReply.Error. Farmer passes them on
// to the CLI as its close reason.
const (
	CodeShellDisabled   = payloadbox.CloseShellDisabled
	CodeShellNotAllowed = payloadbox.CloseShellNotAllowed
	CodeTooManySessions = payloadbox.CloseTooManySessions
	CodeUnsupported     = payloadbox.CloseUnsupported
	CodeSpawnFailed     = payloadbox.CloseSpawnFailed
)

// IsStartRefusal reports whether code is one of the sprout's refusal
// codes.
func IsStartRefusal(code string) bool {
	switch code {
	case CodeShellDisabled, CodeShellNotAllowed, CodeTooManySessions, CodeUnsupported, CodeSpawnFailed:
		return true
	}
	return false
}

// ValidSessionID reports whether id is a session ID farmer could have
// made (payloadbox.NewID: 128 random bits, lowercase hex). Nothing else
// may go into a subject.
func ValidSessionID(id string) bool {
	if len(id) != 32 || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// ValidShellPath reports whether p may be asked for as a shell: empty (the
// default), or an absolute path of printable characters. Whether it is
// allowed is the sprout's allow-list's decision.
func ValidShellPath(p string) bool {
	if p == "" {
		return true
	}
	if len(p) > 256 || !strings.HasPrefix(p, "/") {
		return false
	}
	for _, r := range p {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

// Subjects. Nothing secret goes in a subject: the session ID is routing
// metadata.

// CLISubject is leg 1's subject for dir (payloadbox.DirC2F or DirF2C).
func CLISubject(sessionID, dir string) string {
	return "imas.shell.cli." + sessionID + "." + dir
}

// StartSubject is where farmer sends f2s.shell.start to sproutID.
func StartSubject(sproutID string) string {
	return "imas.sprouts." + sproutID + ".shell.start"
}

// SproutInSubject is leg 2's f2s subject: inside the sprout's
// imas.sprouts.<id>.> subscribe grant.
func SproutInSubject(sproutID, sessionID string) string {
	return "imas.sprouts." + sproutID + ".shell." + sessionID + "." + payloadbox.DirF2S
}

// SproutOutSubjectPrefix is the prefix of every s2f subject sproutID
// publishes on: its User JWT's publish grant is this plus ".>"
// (internal/pki's sproutPermissions). Outside imas.sprouts.<id>.>, so the
// sprout never receives its own frames.
func SproutOutSubjectPrefix(sproutID string) string {
	return "imas.shell.sprout." + sproutID
}

// SproutOutSubject is leg 2's s2f subject.
func SproutOutSubject(sproutID, sessionID string) string {
	return SproutOutSubjectPrefix(sproutID) + "." + sessionID + "." + payloadbox.DirS2F
}

// Transcript builds a leg's key schedule transcript. tenantID, sproutID,
// userID and sessionID are the same on both legs; the ephemeral keys are
// the leg's (initiator first: the CLI on leg 1, farmer on leg 2).
func Transcript(leg, tenantID, sproutID, userID, sessionID string, initiatorEph, responderEph []byte) payloadbox.StreamTranscript {
	return payloadbox.StreamTranscript{
		Leg: leg, TenantID: tenantID, SproutID: sproutID, UserID: userID, SessionID: sessionID,
		InitiatorEph: initiatorEph, ResponderEph: responderEph,
	}
}

// exitCodeNone is a CLOSE's exit code when the shell didn't exit on its
// own.
const exitCodeNone = -1
