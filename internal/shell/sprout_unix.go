//go:build !windows

package shell

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// outputFlushDelay is how long the sprout waits for more PTY output
// before sending what it has, to keep the frame rate down.
const outputFlushDelay = 10 * time.Millisecond

// outputDrainTimeout bounds how long, after the shell exits, the sprout
// waits for the rest of its output before closing. A background job
// holding the terminal open would otherwise keep the session up.
const outputDrainTimeout = 2 * time.Second

func plaintextRefusal(bool) *nats.Msg { return refusal(payloadbox.ErrorCodeEncryptionRequired) }

// sproutSession is one running shell.
type sproutSession struct {
	sp     *Sprout
	id     string
	user   StartUser
	stream *payloadbox.Stream
	keys   *payloadbox.StreamKeys
	cmd    *exec.Cmd
	ptmx   *os.File
	sub    *nats.Subscription
	idle   time.Duration
	maxDur time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	input  chan struct{}
	ended  chan endRequest
	once   sync.Once
}

type endRequest struct {
	reason string
	exit   int
}

// spawn applies local policy and, if it allows, spawns the PTY and
// subscribes to the session's f2s subject. It never spawns for a start
// it refuses.
func (sp *Sprout) spawn(msg *payloadbox.Message, body *StartBody) (StartReply, *sproutSession) {
	pol := CurrentSproutPolicy()
	if pol.Disabled {
		return StartReply{Error: CodeShellDisabled}, nil
	}
	if !validStart(msg, body) {
		return StartReply{Error: CodeSpawnFailed}, nil
	}
	shellPath, ok := pickShell(body.Shell, pol.allowedShells())
	if !ok {
		return StartReply{Error: CodeShellNotAllowed}, nil
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if len(sp.sessions) >= pol.maxSessions() {
		return StartReply{Error: CodeTooManySessions}, nil
	}
	if _, dup := sp.sessions[body.SessionID]; dup {
		return StartReply{Error: CodeSpawnFailed}, nil
	}

	eph, err := payloadbox.NewEphemeralKey()
	if err != nil {
		return StartReply{Error: CodeSpawnFailed}, nil
	}
	ephPub := eph.PublicKey().Bytes()
	keys, err := payloadbox.DeriveStreamKeys(eph, body.FarmerEphPub,
		Transcript(payloadbox.LegSprout, msg.TenantID, sp.id, body.User.Pubkey, body.SessionID, body.FarmerEphPub, ephPub))
	if err != nil {
		return StartReply{Error: CodeSpawnFailed}, nil
	}
	out := SproutOutSubject(sp.id, body.SessionID)
	stream, err := payloadbox.NewStream(keys, false, func(frame []byte) error {
		m := nats.NewMsg(out)
		m.Header.Set(payloadbox.Header, payloadbox.HeaderShell1)
		m.Data = frame
		return sp.nc.PublishMsg(m)
	}, sp.Stream)
	if err != nil {
		keys.Wipe()
		return StartReply{Error: CodeSpawnFailed}, nil
	}

	cmd := exec.Command(shellPath)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	// Its own session and process group (pty sets Setsid and Setctty),
	// killed whole on close; on Linux also killed if the sprout dies.
	cmd.SysProcAttr = shellSysProcAttr()
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(body.Cols), Rows: uint16(body.Rows)})
	if err != nil {
		keys.Wipe()
		log.Warnf("shell: session %s: spawning the shell failed", body.SessionID)
		return StartReply{Error: CodeSpawnFailed}, nil
	}
	s := &sproutSession{
		sp: sp, id: body.SessionID, user: body.User, stream: stream, keys: keys, cmd: cmd, ptmx: ptmx,
		idle:   capDuration(body.IdleTimeoutSec, MaxIdleTimeout),
		maxDur: capDuration(body.MaxDurationSec, MaxSessionDuration),
		input:  make(chan struct{}, 1), ended: make(chan endRequest, 4),
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.sub, err = sp.nc.Subscribe(SproutInSubject(sp.id, body.SessionID), func(m *nats.Msg) { _ = stream.Deliver(m.Data) })
	if err != nil {
		s.kill()
		keys.Wipe()
		return StartReply{Error: CodeSpawnFailed}, nil
	}
	sp.sessions[s.id] = s
	log.Infof("shell: session %s opened for %s (%s)", s.id, userLabel(s.user), shellPath)
	return StartReply{SproutEphPub: ephPub}, s
}

// capDuration is sec seconds, capped at limit; 0 or less is limit.
func capDuration(sec int, limit time.Duration) time.Duration {
	d := time.Duration(sec) * time.Second
	if d <= 0 || d > limit {
		return limit
	}
	return d
}

// abort ends a session whose start reply never went out.
func (s *sproutSession) abort() { s.end(payloadbox.CloseSpawnFailed, exitCodeNone) }

func (s *sproutSession) requestEnd(reason string, exit int) {
	select {
	case s.ended <- endRequest{reason, exit}:
	default:
	}
}

// run drives the session until it ends.
func (s *sproutSession) run() {
	go func() {
		if err := s.stream.Run(s.ctx); errors.Is(err, payloadbox.ErrStreamPeerLost) {
			s.requestEnd(payloadbox.ClosePeerLost, exitCodeNone)
		}
	}()
	go s.inputLoop()
	outputDone := make(chan struct{})
	go s.outputLoop(outputDone)
	go func() {
		code := 0
		if err := s.cmd.Wait(); err != nil {
			code = exitCodeNone
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			}
		}
		select {
		case <-outputDone:
		case <-time.After(outputDrainTimeout):
		}
		s.requestEnd(payloadbox.CloseExit, code)
	}()

	idle := time.NewTimer(s.idle)
	defer idle.Stop()
	maxDur := time.NewTimer(s.maxDur)
	defer maxDur.Stop()
	for {
		select {
		case <-s.input:
			idle.Reset(s.idle)
		case <-idle.C:
			s.end(payloadbox.CloseIdle, exitCodeNone)
			return
		case <-maxDur.C:
			s.end(payloadbox.CloseMaxDuration, exitCodeNone)
			return
		case r := <-s.ended:
			s.end(r.reason, r.exit)
			return
		case <-s.stream.Done():
			reason := payloadbox.CloseIntegrity
			if errors.Is(s.stream.Err(), payloadbox.ErrStreamPeerLost) {
				reason = payloadbox.ClosePeerLost
			}
			s.end(reason, exitCodeNone)
			return
		}
	}
}

// inputLoop applies farmer's frames: input to the PTY, resizes, and
// farmer's CLOSE. It may block writing to the PTY; the stream keeps
// processing ACKs meanwhile, and the window bounds what queues.
func (s *sproutSession) inputLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case f := <-s.stream.Frames():
			switch f.Type {
			case payloadbox.FrameData:
				select {
				case s.input <- struct{}{}:
				default:
				}
				if _, err := s.ptmx.Write(f.Payload); err != nil {
					s.requestEnd(payloadbox.CloseExit, exitCodeNone)
					return
				}
				s.stream.Consumed(f)
			case payloadbox.FrameResize:
				if cols, rows, err := payloadbox.DecodeTerminalSize(f.Payload); err == nil {
					_ = pty.Setsize(s.ptmx, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
				}
				s.stream.Consumed(f)
			case payloadbox.FrameClose:
				// Farmer ended the session (the user left, or farmer's
				// policy ended it): its reason is the one recorded.
				info, err := payloadbox.DecodeClose(f.Payload)
				if err != nil {
					info.Reason = payloadbox.CloseIntegrity
				}
				s.requestEnd(info.Reason, exitCodeNone)
				return
			}
		}
	}
}

// outputLoop reads the PTY and sends what it reads as DATA, up to
// payloadbox.MaxFrameData at a time, flushing after outputFlushDelay
// without more output. SendData blocks while farmer's window is full, so
// a full window stops the reading.
func (s *sproutSession) outputLoop(done chan<- struct{}) {
	defer close(done)
	chunks := make(chan []byte, 4)
	go func() {
		defer close(chunks)
		for {
			buf := make([]byte, payloadbox.MaxFrameData)
			n, err := s.ptmx.Read(buf)
			if n > 0 {
				select {
				case chunks <- buf[:n]:
				case <-s.ctx.Done():
					return
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.EIO) && !errors.Is(err, os.ErrClosed) {
					log.Debugf("shell: session %s: reading the terminal stopped", s.id)
				}
				return
			}
		}
	}()
	var pending []byte
	flush := func() bool {
		if len(pending) == 0 {
			return true
		}
		err := s.stream.SendData(s.ctx, pending)
		pending = pending[:0]
		return err == nil
	}
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	for {
		select {
		case c, ok := <-chunks:
			if !ok {
				flush()
				return
			}
			pending = append(pending, c...)
			if len(pending) >= payloadbox.MaxFrameData {
				if !flush() {
					return
				}
			} else {
				timer.Reset(outputFlushDelay)
			}
		case <-timer.C:
			if !flush() {
				return
			}
		case <-s.ctx.Done():
			return
		}
	}
}

// end closes the session once: CLOSE to farmer, the whole process group
// killed, the subscription dropped.
func (s *sproutSession) end(reason string, exit int) {
	s.once.Do(func() {
		if err := s.stream.Close(payloadbox.CloseInfo{Reason: reason, ExitCode: int32(exit)}); err != nil {
			log.Debugf("shell: session %s: sending CLOSE: %v", s.id, err)
		}
		if s.cancel != nil {
			s.cancel()
		}
		if s.sub != nil {
			_ = s.sub.Unsubscribe()
		}
		s.kill()
		s.keys.Wipe()
		s.sp.mu.Lock()
		delete(s.sp.sessions, s.id)
		s.sp.mu.Unlock()
		log.Infof("shell: session %s for %s ended: %s", s.id, userLabel(s.user), reason)
	})
}

// kill kills the shell's whole process group and closes the PTY.
func (s *sproutSession) kill() {
	if s.cmd != nil && s.cmd.Process != nil {
		// Setsid made the shell its group's leader: -pid is the group.
		_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		_ = s.cmd.Process.Kill()
	}
	if s.ptmx != nil {
		_ = s.ptmx.Close()
	}
}

// CloseAll ends every session (the sprout is stopping), so no shell
// outlives it even where there is no Pdeathsig.
func (sp *Sprout) CloseAll() {
	sp.mu.Lock()
	all := make([]*sproutSession, 0, len(sp.sessions))
	for _, s := range sp.sessions {
		all = append(all, s)
	}
	sp.mu.Unlock()
	for _, s := range all {
		s.end(payloadbox.CloseSproutShutdown, exitCodeNone)
	}
}
