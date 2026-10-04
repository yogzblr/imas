package natsapi

// Sealed shell, farmer's side: the relay between leg 1 (the CLI) and
// leg 2 (the sprout) (docs/design/imas-payload-encryption-design.md,
// "Sealing shell.*", Decision 1 shape C; J.5). FLAG FOR SECURITY REVIEW.
//
// imas.api.shell.open goes through the sealed router like every method:
// it must open under the user's registered CLI box key (purpose
// c2f.shell.open; no bearer token, no NKey signature), pass the replay
// guard and the cluster-wide claim (it is mutating), and the user's role
// must grant shell on that sprout in this tenant (authorize). Then
// handleShellOpen checks the sprout is an accepted sprout of this tenant
// ((tenant_id, sprout_id), never sprout_id alone) with a box key,
// applies farmer's limits, picks the session ID and an ephemeral key, and
// answers. The sprout is contacted only after the CLI's HELLO opens
// (key confirmation): a replayed open gets a reply nobody can use.
//
// While a session runs, the owning replica copies frames between the two
// legs, and ends the session (CLOSE on both legs) on: either end's CLOSE,
// a frame that fails (integrity), silence (peer-lost), idle input, the
// maximum duration, the user losing shell on that sprout (revoked,
// re-checked every 60 s), or the tenant key its leg 2 handshake used
// leaving the tenant's key set (key-severed, re-checked every 60 s and at
// once after a rotation on this replica). Sessions live in this replica's
// memory only, keyed (tenant_id, session_id): they die with the replica,
// and v1 has no cross-replica list (owner decision 2026-10-04). There is
// no plaintext fallback of any kind, and no transcript: only audit
// entries when a session starts and ends.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/taigrr/jety"

	"github.com/yogzblr/imas/internal/audit"
	intauth "github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/rbac"
	"github.com/yogzblr/imas/internal/shell"
)

// Farmer's shell policy. Variables so tests can shorten them.
var (
	// shellLimits caps concurrent sessions on one replica: per user, per
	// tenant and in all.
	shellLimits = shell.Limits{PerUser: 4, PerTenant: 64, PerReplica: 256}
	// shellRecheckInterval is how often a running session's user is
	// re-authorized and its tenant key re-checked.
	shellRecheckInterval = 60 * time.Second
	// shellKeyRecheckAfter is how old a tenant's cached key versions may
	// be before a recheck re-reads them from OpenBao.
	shellKeyRecheckAfter = 30 * time.Second
	shellHelloTimeout    = shell.HelloTimeout
	shellStartTimeout    = shell.StartTimeout
	shellStreamOptions   payloadbox.StreamOptions
)

// shellIdleTimeout is farmer's idle timeout: config "shellidletimeout",
// default 15 minutes, at most 60.
func shellIdleTimeout() time.Duration {
	d := jety.GetDuration("shellidletimeout")
	switch {
	case d <= 0:
		return shell.DefaultIdleTimeout
	case d > shell.MaxIdleTimeout:
		log.Warnf("natsapi: shellidletimeout %s is above the %s maximum; using %s", d, shell.MaxIdleTimeout, shell.MaxIdleTimeout)
		return shell.MaxIdleTimeout
	}
	return d
}

// shellMaxDuration is the longest a session may last: config
// "shellmaxduration", default and at most 8 hours.
func shellMaxDuration() time.Duration {
	d := jety.GetDuration("shellmaxduration")
	if d <= 0 || d > shell.MaxSessionDuration {
		return shell.MaxSessionDuration
	}
	return d
}

// ErrShellUnavailable is handleShellOpen's answer when the session can't
// be opened. Its text travels inside the sealed reply only.
var (
	errShellUnknownSprout = errors.New("unknown sprout")
	errShellNoBoxKey      = errors.New("the sprout has no payload-encryption key on record; re-enroll it (shell has no plaintext fallback)")
	errShellTooMany       = errors.New("too many shell sessions open; close one and retry")
)

// shellRegistry is this replica's running sessions.
type shellRegistry struct {
	tracker *shell.Tracker

	mu   sync.Mutex
	live map[shell.SessionKey]*farmerShell

	keysMu sync.Mutex
	keys   map[string]tenantKeyVersions
}

type tenantKeyVersions struct {
	versions map[int]bool
	read     time.Time
}

var shellSessions = &shellRegistry{
	tracker: shell.NewTracker(), live: map[shell.SessionKey]*farmerShell{}, keys: map[string]tenantKeyVersions{},
}

// ShellTracker is this replica's session list.
func ShellTracker() *shell.Tracker { return shellSessions.tracker }

// CloseShellSessions ends every session this replica relays, with
// farmer-shutdown, so both ends learn at once instead of after the
// heartbeat timeout. For farmer's shutdown path.
func CloseShellSessions() {
	for _, s := range shellSessions.all() {
		s.kill(payloadbox.CloseFarmerShutdown)
	}
}

func (r *shellRegistry) all() []*farmerShell {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*farmerShell, 0, len(r.live))
	for _, s := range r.live {
		out = append(out, s)
	}
	return out
}

func (r *shellRegistry) add(s *farmerShell) bool {
	if !r.tracker.TryAdd(s.info, shellLimits) {
		return false
	}
	r.mu.Lock()
	r.live[s.key] = s
	r.mu.Unlock()
	return true
}

func (r *shellRegistry) remove(s *farmerShell) {
	r.tracker.Remove(s.key)
	r.mu.Lock()
	delete(r.live, s.key)
	r.mu.Unlock()
}

// keyVersions returns tenantID's current key versions (the ones farmer
// seals and opens under), re-read from OpenBao when the cached copy is
// older than shellKeyRecheckAfter, or force.
func (r *shellRegistry) keyVersions(tenantID string, force bool) (map[int]bool, error) {
	r.keysMu.Lock()
	defer r.keysMu.Unlock()
	if c, ok := r.keys[tenantID]; ok && !force && time.Since(c.read) < shellKeyRecheckAfter {
		return c.versions, nil
	}
	pki.InvalidateTenantBoxKeys(tenantID)
	keys, err := pki.TenantBoxKeys(tenantID)
	if err != nil {
		return nil, err
	}
	v := make(map[int]bool, len(keys))
	for _, k := range keys {
		v[k.Version] = true
	}
	r.keys[tenantID] = tenantKeyVersions{versions: v, read: time.Now()}
	return v, nil
}

// recheckTenantKeys re-reads tenantID's keys now and ends, with
// key-severed, every session of that tenant whose leg 2 used a key no
// longer among them. Called after a tenant key rotation on this replica;
// other replicas notice within shellRecheckInterval.
func (r *shellRegistry) recheckTenantKeys(tenantID string) {
	versions, err := r.keyVersions(tenantID, true)
	if err != nil {
		log.Warnf("natsapi: re-reading tenant %s keys for shell sessions: %v", tenantID, err)
		return
	}
	for _, s := range r.all() {
		if s.key.TenantID == tenantID && s.leg2Version() != 0 && !versions[s.leg2Version()] {
			s.kill(payloadbox.CloseKeySevered)
		}
	}
}

// farmerShell is one relayed session.
type farmerShell struct {
	key    shell.SessionKey
	info   *shell.SessionInfo
	nc     *nats.Conn
	idle   time.Duration
	maxDur time.Duration

	leg1, leg2 *payloadbox.Stream
	keys1      *payloadbox.StreamKeys
	keys2      *payloadbox.StreamKeys
	sub1, sub2 *nats.Subscription

	mu        sync.Mutex
	version   int      // tenant key version leg 2's handshake used
	preLeg2   [][]byte // s2f frames that arrived before leg 2's keys
	preDrop   bool
	ctx       context.Context
	cancel    context.CancelFunc
	killCh    chan string
	endOnce   sync.Once
	started   bool
	startedAt time.Time
}

func (s *farmerShell) leg2Version() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

// kill asks the session to end with reason.
func (s *farmerShell) kill(reason string) {
	select {
	case s.killCh <- reason:
	default:
	}
}

func handleShellOpen(c apiCaller, params json.RawMessage) (any, error) {
	var req shell.OpenRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	if !pki.IsValidSproutID(req.SproutID) {
		return nil, fmt.Errorf("invalid sprout ID")
	}
	if !shell.ValidShellPath(req.Shell) {
		return nil, fmt.Errorf("shell must be an absolute path")
	}
	if req.IdleTimeoutSec < 0 {
		return nil, fmt.Errorf("idle_timeout_sec must not be negative")
	}
	if len(req.CLIEphPub) != 32 {
		return nil, fmt.Errorf("invalid ephemeral key")
	}
	var eph [32]byte
	copy(eph[:], req.CLIEphPub)
	if payloadbox.CheckPublicKey(&eph) != nil {
		return nil, fmt.Errorf("invalid ephemeral key")
	}
	tenantKeys, err := pki.TenantBoxKeys(c.TenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant keys unavailable")
	}
	for _, tk := range tenantKeys {
		if *tk.Pub == eph {
			return nil, fmt.Errorf("invalid ephemeral key")
		}
	}
	// The sprout must be an accepted sprout of this tenant, with a box
	// key: shell has no plaintext path.
	if err := pki.VerifySproutInTenant(c.TenantID, req.SproutID); err != nil {
		if errors.Is(err, pki.ErrSproutIDNotFound) || errors.Is(err, pki.ErrTenantNotFound) || errors.Is(err, pki.ErrSproutIDInvalid) {
			return nil, errShellUnknownSprout
		}
		return nil, fmt.Errorf("checking the sprout: %w", err)
	}
	if _, _, err := pki.ValidSproutBoxKeys(c.TenantID, req.SproutID); err != nil {
		if errors.Is(err, pki.ErrNoActiveBoxKey) {
			return nil, errShellNoBoxKey
		}
		return nil, fmt.Errorf("checking the sprout's box key: %w", err)
	}
	nc := natsConnFor(c.TenantID)
	if nc == nil {
		return nil, fmt.Errorf("NATS connection not available")
	}

	idle := shellIdleTimeout()
	if req.IdleTimeoutSec > 0 && time.Duration(req.IdleTimeoutSec)*time.Second < idle {
		idle = time.Duration(req.IdleTimeoutSec) * time.Second
	}
	maxDur := shellMaxDuration()

	sessionID, err := payloadbox.NewID()
	if err != nil {
		return nil, err
	}
	farmerEph, err := payloadbox.NewEphemeralKey()
	if err != nil {
		return nil, err
	}
	farmerPub := farmerEph.PublicKey().Bytes()
	keys1, err := payloadbox.DeriveStreamKeys(farmerEph, req.CLIEphPub,
		shell.Transcript(payloadbox.LegCLI, c.TenantID, req.SproutID, c.UserID, sessionID, req.CLIEphPub, farmerPub))
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral key")
	}
	roleName, username := intauth.UserIdentity(c.UserID)
	s := &farmerShell{
		key: shell.SessionKey{TenantID: c.TenantID, SessionID: sessionID},
		info: &shell.SessionInfo{
			TenantID: c.TenantID, SessionID: sessionID, SproutID: req.SproutID, Pubkey: c.UserID,
			Username: username, RoleName: roleName, Shell: req.Shell, StartedAt: time.Now().UTC(),
		},
		nc: nc, idle: idle, maxDur: maxDur, keys1: keys1,
		killCh: make(chan string, 4),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	f2c := shell.CLISubject(sessionID, payloadbox.DirF2C)
	s.leg1, err = payloadbox.NewStream(keys1, false, func(frame []byte) error { return publishFrame(nc, f2c, frame) }, shellStreamOptions)
	if err != nil {
		keys1.Wipe()
		return nil, err
	}
	if !shellSessions.add(s) {
		keys1.Wipe()
		return nil, errShellTooMany
	}
	s.sub1, err = nc.Subscribe(shell.CLISubject(sessionID, payloadbox.DirC2F), func(m *nats.Msg) { _ = s.leg1.Deliver(m.Data) })
	if err == nil {
		err = nc.Flush()
	}
	if err != nil {
		s.cleanup()
		return nil, fmt.Errorf("subscribing to the session: %w", err)
	}
	go s.run()
	log.Infof("natsapi: shell session %s offered to %s for sprout %s (tenant %s)", sessionID, c.UserID, req.SproutID, c.TenantID)
	return shell.OpenResult{
		SessionID: sessionID, SproutID: req.SproutID, FarmerEphPub: farmerPub,
		IdleTimeoutSec: int(idle / time.Second), MaxDurationSec: int(maxDur / time.Second),
	}, nil
}

func publishFrame(nc *nats.Conn, subject string, frame []byte) error {
	m := nats.NewMsg(subject)
	m.Header.Set(payloadbox.Header, payloadbox.HeaderShell1)
	m.Data = frame
	return nc.PublishMsg(m)
}

// cleanup drops a session that never ran.
func (s *farmerShell) cleanup() {
	s.cancel()
	if s.sub1 != nil {
		_ = s.sub1.Unsubscribe()
	}
	s.keys1.Wipe()
	shellSessions.remove(s)
}

// run waits for key confirmation, starts leg 2 and relays.
func (s *farmerShell) run() {
	// Key confirmation: HELLO, the CLI's first frame, opened under leg 1's
	// keys. Until then nothing reaches the sprout.
	var hello payloadbox.Frame
	select {
	case hello = <-s.leg1.Frames():
	case <-time.After(shellHelloTimeout):
		log.Infof("natsapi: shell session %s: no HELLO within %s; dropped without contacting the sprout", s.key.SessionID, shellHelloTimeout)
		s.auditStart(false, "no-hello")
		s.cleanup()
		return
	case <-s.leg1.Done():
		log.Warnf("natsapi: shell session %s: the CLI's first frame failed to open; dropped", s.key.SessionID)
		s.auditStart(false, payloadbox.CloseIntegrity)
		_ = s.leg1.Close(payloadbox.CloseInfo{Reason: payloadbox.CloseIntegrity, ExitCode: -1})
		s.cleanup()
		return
	case reason := <-s.killCh:
		s.auditStart(false, reason)
		_ = s.leg1.Close(payloadbox.CloseInfo{Reason: reason, ExitCode: -1})
		s.cleanup()
		return
	}
	cols, rows, _ := payloadbox.DecodeTerminalSize(hello.Payload) // checked by the stream

	if code := s.startLeg2(cols, rows); code != "" {
		s.auditStart(false, code)
		_ = s.leg1.Close(payloadbox.CloseInfo{Reason: code, ExitCode: -1})
		s.cleanup()
		if s.sub2 != nil {
			_ = s.sub2.Unsubscribe()
		}
		if s.keys2 != nil {
			s.keys2.Wipe()
		}
		return
	}
	if err := s.leg1.SendReady(); err != nil {
		s.end(payloadbox.ClosePeerLost, -1)
		return
	}
	s.mu.Lock()
	s.started, s.startedAt = true, time.Now()
	s.mu.Unlock()
	s.auditStart(true, "")
	log.Infof("natsapi: shell session %s started (user %s, sprout %s, tenant %s)", s.key.SessionID, s.info.Pubkey, s.info.SproutID, s.key.TenantID)
	s.relay()
}

// startLeg2 sends the sealed start and sets leg 2 up from the sprout's
// sealed answer. It returns "" or the close reason the CLI gets.
func (s *farmerShell) startLeg2(cols, rows int) string {
	eph, err := payloadbox.NewEphemeralKey()
	if err != nil {
		return payloadbox.CloseSpawnFailed
	}
	ephPub := eph.PublicKey().Bytes()
	body := shell.StartBody{
		SessionID: s.key.SessionID, FarmerEphPub: ephPub, Cols: cols, Rows: rows, Shell: s.info.Shell,
		IdleTimeoutSec: int(s.idle / time.Second), MaxDurationSec: int(s.maxDur / time.Second),
		User: shell.StartUser{Pubkey: s.info.Pubkey, Name: s.info.Username},
	}
	data, reqID, err := pki.SealToSprout(s.key.TenantID, s.info.SproutID, payloadbox.PurposeShellStart, "", body)
	if err != nil {
		// No box key (re-enroll), or keys unreadable: never plaintext.
		log.Warnf("natsapi: shell session %s: sealing the start for %s: %v", s.key.SessionID, s.info.SproutID, err)
		return payloadbox.CloseSproutRefused
	}
	// Subscribe to the sprout's frames before it can send any: it may
	// print a prompt the moment the PTY is up. They wait in preLeg2 until
	// leg 2's keys are known.
	s.sub2, err = s.nc.Subscribe(shell.SproutOutSubject(s.info.SproutID, s.key.SessionID), s.deliverS2F)
	if err == nil {
		err = s.nc.Flush()
	}
	if err != nil {
		return payloadbox.CloseSproutUnreachable
	}
	m := nats.NewMsg(shell.StartSubject(s.info.SproutID))
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Data = data
	reply, err := s.nc.RequestMsg(m, shellStartTimeout)
	if err != nil {
		log.Warnf("natsapi: shell session %s: sprout %s did not answer the start: %v", s.key.SessionID, s.info.SproutID, err)
		return payloadbox.CloseSproutUnreachable
	}
	if code := reply.Header.Get(payloadbox.ErrorHeader); code != "" {
		log.Warnf("natsapi: shell session %s: sprout %s refused the sealed start: %s", s.key.SessionID, s.info.SproutID, code)
		return payloadbox.CloseSproutRefused
	}
	if reply.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		// An old sprout build (it can't read the start), or a bus
		// attempting a downgrade. Never retried in plaintext.
		log.Warnf("natsapi: shell session %s: sprout %s answered the sealed start in plaintext; it needs upgrading", s.key.SessionID, s.info.SproutID)
		return payloadbox.CloseSproutNeedsUpdate
	}
	msg, version, err := openShellStartReply(s.key.TenantID, s.info.SproutID, reqID, reply.Data)
	if err != nil {
		log.Warnf("natsapi: shell session %s: the sprout's answer did not open: %v", s.key.SessionID, err)
		return payloadbox.CloseSproutRefused
	}
	var ans shell.StartReply
	if err := json.Unmarshal(msg.Body, &ans); err != nil {
		return payloadbox.CloseSproutRefused
	}
	if ans.Error != "" {
		if !shell.IsStartRefusal(ans.Error) {
			return payloadbox.CloseSpawnFailed
		}
		return ans.Error
	}
	keys2, err := payloadbox.DeriveStreamKeys(eph, ans.SproutEphPub,
		shell.Transcript(payloadbox.LegSprout, s.key.TenantID, s.info.SproutID, s.info.Pubkey, s.key.SessionID, ephPub, ans.SproutEphPub))
	if err != nil {
		return payloadbox.CloseSproutRefused
	}
	s.keys2 = keys2
	f2s := shell.SproutInSubject(s.info.SproutID, s.key.SessionID)
	leg2, err := payloadbox.NewStream(keys2, true, func(frame []byte) error { return publishFrame(s.nc, f2s, frame) }, shellStreamOptions)
	if err != nil {
		return payloadbox.CloseSpawnFailed
	}
	s.mu.Lock()
	s.leg2, s.version = leg2, version
	pre, dropped := s.preLeg2, s.preDrop
	s.preLeg2 = nil
	s.mu.Unlock()
	if dropped {
		_ = leg2.Close(payloadbox.CloseInfo{Reason: payloadbox.CloseIntegrity, ExitCode: -1})
		return payloadbox.CloseIntegrity
	}
	for _, f := range pre {
		_ = leg2.Deliver(f)
	}
	return ""
}

// maxPreLeg2Frames bounds what is held before leg 2's keys are known:
// the sprout can't have sent more than its window.
const maxPreLeg2Frames = payloadbox.DefaultStreamMaxUnackedFrames + 8

// deliverS2F is the s2f subscription's handler.
func (s *farmerShell) deliverS2F(m *nats.Msg) {
	s.mu.Lock()
	leg2 := s.leg2
	if leg2 == nil {
		if len(s.preLeg2) >= maxPreLeg2Frames {
			s.preDrop = true
		} else {
			s.preLeg2 = append(s.preLeg2, append([]byte(nil), m.Data...))
		}
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	_ = leg2.Deliver(m.Data)
}

// openShellStartReply opens the sprout's s2f.shell.start answer to the
// start reqID, and says which tenant key version it opened under.
func openShellStartReply(tenantID, sproutID, reqID string, data []byte) (*payloadbox.Message, int, error) {
	active, grace, err := pki.ValidSproutBoxKeys(tenantID, sproutID)
	if err != nil {
		return nil, 0, err
	}
	var sproutPubs []*[32]byte
	for _, p := range append([]string{active}, grace...) {
		if pub, err := pki.DecodeBoxPubKey(p); err == nil {
			sproutPubs = append(sproutPubs, pub)
		}
	}
	tenantKeys, err := pki.TenantBoxKeys(tenantID)
	if err != nil {
		return nil, 0, err
	}
	want := payloadbox.Expect{Purpose: payloadbox.PurposeShellStartReply, TenantID: tenantID, SproutID: sproutID}
	for _, tk := range tenantKeys {
		candidates := make([]payloadbox.KeyPair, 0, len(sproutPubs))
		for _, sp := range sproutPubs {
			candidates = append(candidates, payloadbox.KeyPair{PeerPub: sp, Priv: tk.Priv})
		}
		msg, err := payloadbox.Open(data, candidates, want)
		if err != nil {
			continue
		}
		if msg.ReplyTo != reqID {
			return nil, 0, payloadbox.ErrOpen
		}
		return msg, tk.Version, nil
	}
	return nil, 0, payloadbox.ErrOpen
}

// relay copies frames between the legs until the session ends.
func (s *farmerShell) relay() {
	ended := make(chan endReason, 4)
	request := func(reason string, exit int) {
		select {
		case ended <- endReason{reason, exit}:
		default:
		}
	}
	input := make(chan struct{}, 1)
	for _, leg := range []*payloadbox.Stream{s.leg1, s.leg2} {
		go func() {
			if err := leg.Run(s.ctx); errors.Is(err, payloadbox.ErrStreamPeerLost) {
				request(payloadbox.ClosePeerLost, -1)
			}
		}()
	}
	// CLI -> sprout.
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			case f := <-s.leg1.Frames():
				switch f.Type {
				case payloadbox.FrameData:
					select {
					case input <- struct{}{}:
					default:
					}
					if s.leg2.SendData(s.ctx, f.Payload) != nil {
						return
					}
					s.leg1.Consumed(f)
				case payloadbox.FrameResize:
					cols, rows, _ := payloadbox.DecodeTerminalSize(f.Payload)
					if s.leg2.SendResize(s.ctx, cols, rows) != nil {
						return
					}
					s.leg1.Consumed(f)
				case payloadbox.FrameClose:
					request(payloadbox.CloseClientClose, -1)
					return
				}
			}
		}
	}()
	// Sprout -> CLI.
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			case f := <-s.leg2.Frames():
				switch f.Type {
				case payloadbox.FrameData:
					if s.leg1.SendData(s.ctx, f.Payload) != nil {
						return
					}
					s.leg2.Consumed(f)
				case payloadbox.FrameClose:
					// The sprout's reason and exit code go to the CLI as they
					// are.
					info, err := payloadbox.DecodeClose(f.Payload)
					if err != nil {
						info = payloadbox.CloseInfo{Reason: payloadbox.CloseIntegrity, ExitCode: -1}
					}
					request(info.Reason, int(info.ExitCode))
					return
				}
			}
		}
	}()

	idle := time.NewTimer(s.idle)
	defer idle.Stop()
	maxDur := time.NewTimer(s.maxDur)
	defer maxDur.Stop()
	recheck := time.NewTicker(shellRecheckInterval)
	defer recheck.Stop()
	for {
		select {
		case <-input:
			idle.Reset(s.idle)
		case <-idle.C:
			s.end(payloadbox.CloseIdle, -1)
			return
		case <-maxDur.C:
			s.end(payloadbox.CloseMaxDuration, -1)
			return
		case <-recheck.C:
			if reason := s.recheck(); reason != "" {
				s.end(reason, -1)
				return
			}
		case reason := <-s.killCh:
			s.end(reason, -1)
			return
		case r := <-ended:
			s.end(r.reason, r.exit)
			return
		case <-s.leg1.Done():
			s.end(streamEndReason(s.leg1.Err()), -1)
			return
		case <-s.leg2.Done():
			s.end(streamEndReason(s.leg2.Err()), -1)
			return
		}
	}
}

type endReason struct {
	reason string
	exit   int
}

func streamEndReason(err error) string {
	if errors.Is(err, payloadbox.ErrStreamPeerLost) {
		return payloadbox.ClosePeerLost
	}
	return payloadbox.CloseIntegrity
}

// recheck re-authorizes the session: the user must still exist and have
// shell on this sprout in this tenant, and leg 2's tenant key must still
// be one farmer uses. "" means carry on.
func (s *farmerShell) recheck() string {
	if !intauth.UserHasAction(s.info.Pubkey, rbac.ActionShell) ||
		checkScopedAccess(s.key.TenantID, s.info.Pubkey, rbac.ActionShell, []string{s.info.SproutID}) != nil {
		return payloadbox.CloseRevoked
	}
	versions, err := shellSessions.keyVersions(s.key.TenantID, false)
	if err != nil {
		// OpenBao unreachable: pki keeps serving its cached keys for a
		// while; carry on and check again next time.
		log.Warnf("natsapi: shell session %s: re-reading tenant keys: %v", s.key.SessionID, err)
		return ""
	}
	if !versions[s.leg2Version()] {
		return payloadbox.CloseKeySevered
	}
	return ""
}

// end closes both legs with reason (CLOSE on each, if not sent), drops the
// subscriptions and records the end.
func (s *farmerShell) end(reason string, exit int) {
	s.endOnce.Do(func() {
		info := payloadbox.CloseInfo{Reason: reason, ExitCode: int32(exit)}
		_ = s.leg1.Close(info)
		if s.leg2 != nil {
			toSprout := info
			if reason == payloadbox.CloseExit {
				// The sprout ended it; what it gets back is only a final
				// frame.
				toSprout.Reason = payloadbox.CloseClientClose
			}
			_ = s.leg2.Close(toSprout)
		}
		s.cancel()
		for _, sub := range []*nats.Subscription{s.sub1, s.sub2} {
			if sub != nil {
				_ = sub.Unsubscribe()
			}
		}
		s.keys1.Wipe()
		if s.keys2 != nil {
			s.keys2.Wipe()
		}
		shellSessions.remove(s)
		s.auditEnd(reason, exit)
		log.Infof("natsapi: shell session %s ended: %s (user %s, sprout %s, %s)", s.key.SessionID, reason,
			s.info.Pubkey, s.info.SproutID, time.Since(s.startedAt).Round(time.Second))
	})
}

// auditStart records leg 2's outcome: shell.start, with the fixed code if
// it failed. The router has already recorded the shell.open request.
func (s *farmerShell) auditStart(ok bool, code string) {
	params := map[string]any{"session_id": s.key.SessionID, "sprout_id": s.info.SproutID, "tenant_id": s.key.TenantID}
	if s.info.Shell != "" {
		params["shell"] = s.info.Shell
	}
	if code != "" {
		params["code"] = code
	}
	s.audit("shell.start", params, ok, code)
}

// auditEnd records shell.end: duration, exit code, reason, and the bytes
// and frames each way. Never content.
func (s *farmerShell) auditEnd(reason string, exit int) {
	l1, l2 := s.leg1.Stats(), payloadbox.StreamStats{}
	if s.leg2 != nil {
		l2 = s.leg2.Stats()
	}
	params := map[string]any{
		"session_id": s.key.SessionID, "sprout_id": s.info.SproutID, "tenant_id": s.key.TenantID,
		"duration_sec": time.Since(s.startedAt).Seconds(), "exit_code": exit, "reason": reason,
		"bytes_in": l1.RecvBytes, "frames_in": l1.RecvFrames, "bytes_out": l2.RecvBytes, "frames_out": l2.RecvFrames,
	}
	s.audit("shell.end", params, reason == payloadbox.CloseExit || reason == payloadbox.CloseClientClose, "")
}

func (s *farmerShell) audit(action string, params map[string]any, ok bool, errCode string) {
	logger := audit.Global()
	if logger == nil {
		return
	}
	data, _ := json.Marshal(params)
	entry := audit.Entry{
		Timestamp: time.Now().UTC(), Username: s.info.Username, Pubkey: s.info.Pubkey, RoleName: s.info.RoleName,
		Action: action, Targets: []string{s.info.SproutID}, Parameters: data, Success: ok, Error: errCode,
	}
	if err := logger.Log(entry); err != nil {
		log.Errorf("natsapi: audit log failed for %s: %v", action, err)
	}
}
