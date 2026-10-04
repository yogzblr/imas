package payloadbox

// Sealed shell streams (docs/design/imas-payload-encryption-design.md,
// "Sealing shell.*", Decision 2; J.5). FLAG FOR SECURITY REVIEW.
//
// A shell session has two legs, CLI <-> farmer and farmer <-> sprout. Each
// is set up by a payloadbox handshake (the c2f.shell.open request and its
// reply, and f2s.shell.start / s2f.shell.start) that carries one fresh
// X25519 ephemeral public key from each end of the leg. After that, the
// leg is a stream of numbered frames, one per NATS message, under keys
// derived from those two ephemeral keys alone:
//
//   - Keys. X25519 between the two ephemeral keys (crypto/ecdh, which
//     refuses an all-zero shared secret; CheckPublicKey refuses a
//     low-order peer key first), then HKDF-SHA256 (crypto/hkdf) with the
//     SHA-256 of the handshake transcript as salt, one 32-byte key per
//     direction. The static tenant, sprout and CLI box keys only
//     authenticate the handshake, so recorded shell traffic stays
//     unreadable even if one of them leaks later.
//   - Frames. version (1 byte) | seq (uint64, big-endian) | ciphertext,
//     ChaCha20-Poly1305 (golang.org/x/crypto/chacha20poly1305) with the
//     nonce 4 zero bytes | seq. The key is per direction and seq never
//     repeats in one direction, so no (key, nonce) pair is ever reused.
//     The associated data binds the protocol, the direction, the session,
//     the version and seq. The plaintext is type (1 byte) | payload, so the
//     frame type is hidden too.
//   - Receiving fails closed. A frame is accepted only if its seq is the
//     next one expected and it opens. A lower seq (a replay or duplicate),
//     a higher one (a dropped frame) or one that doesn't open (tampered,
//     another session's, another direction's) fails the stream for good:
//     there is no resynchronisation. A single dropped keystroke can change
//     what a command line does.
//   - Flow control. DATA and RESIZE frames are "windowed": the receiver
//     acknowledges them only once its owner has consumed them (Consumed),
//     and a sender stops (SendData, SendResize block) while more than
//     Window bytes or MaxUnackedFrames frames are unacknowledged. A
//     receiver never blocks in Deliver, and its queue (Frames) can't
//     overflow while the peer respects the window; a peer that doesn't
//     fails the stream (integrity).
//   - Liveness. Run sends a HEARTBEAT after HeartbeatInterval without
//     sending anything, ACKs consumed frames every AckInterval, and fails
//     the stream with ErrStreamPeerLost after PeerTimeout without
//     receiving anything.
//   - Ending. CLOSE is the last frame in each direction: a fixed reason
//     code, an exit code and the number of frames sent before it. It is
//     authenticated like every frame, so a session never appears to end
//     normally when it didn't, and cutting off its tail is visible.
//
// This file does no I/O of its own: Publish is the caller's, and Deliver
// is fed whatever arrives on the leg's receive subject.

import (
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// HeaderShell1 is the payloadbox.Header value on a shell stream frame: a
// hint for diagnostics, never a security decision (like HeaderBox1).
const HeaderShell1 = "shell1"

// Shell handshake purposes (Decision 2). c2f.shell.open is a sealed
// control-plane Call on imas.api.shell.open, answered with an f2c.api
// Reply like every other CLI request (so the CLI's one reply opener,
// internal/pki's CLIOpenReply, opens it); f2s.shell.start and
// s2f.shell.start are request and reply on imas.sprouts.<id>.shell.start.
const (
	PurposeShellOpen       = "c2f.shell.open"
	PurposeShellStart      = "f2s.shell.start"
	PurposeShellStartReply = "s2f.shell.start"
)

// Stream directions. Each leg has two.
const (
	DirC2F = "c2f"
	DirF2C = "f2c"
	DirF2S = "f2s"
	DirS2F = "s2f"
)

// Legs. The initiator of a leg is the end that sent its handshake
// request: the CLI on LegCLI, farmer on LegSprout.
const (
	LegCLI    = "cli"
	LegSprout = "sprout"
)

// StreamVersion is the only frame version this package reads or writes.
const StreamVersion = 1

// FrameType is a frame's type, inside the ciphertext.
type FrameType byte

const (
	// FrameHello is the CLI's first frame (c2f, seq 0): key confirmation,
	// carrying the terminal size. Farmer contacts the sprout only after it.
	FrameHello FrameType = 1
	// FrameReady is farmer's first frame (f2c, seq 0): the sprout spawned
	// the PTY.
	FrameReady FrameType = 2
	// FrameData carries terminal bytes: input toward the sprout, output
	// toward the CLI. Windowed.
	FrameData FrameType = 3
	// FrameResize carries a new terminal size (c2f, f2s). Windowed.
	FrameResize FrameType = 4
	// FrameAck acknowledges consumed frames: every frame with a lower seq
	// than its value was received and consumed. Handled by the stream.
	FrameAck FrameType = 5
	// FrameHeartbeat proves the sender is alive. Handled by the stream.
	FrameHeartbeat FrameType = 6
	// FrameClose is the last frame in its direction.
	FrameClose FrameType = 7
)

func (t FrameType) String() string {
	switch t {
	case FrameHello:
		return "HELLO"
	case FrameReady:
		return "READY"
	case FrameData:
		return "DATA"
	case FrameResize:
		return "RESIZE"
	case FrameAck:
		return "ACK"
	case FrameHeartbeat:
		return "HEARTBEAT"
	case FrameClose:
		return "CLOSE"
	}
	return fmt.Sprintf("frame(%d)", byte(t))
}

// allowedFrames are the frame types each direction may carry; any other
// fails the stream.
var allowedFrames = map[string]map[FrameType]bool{
	DirC2F: {FrameHello: true, FrameData: true, FrameResize: true, FrameAck: true, FrameHeartbeat: true, FrameClose: true},
	DirF2C: {FrameReady: true, FrameData: true, FrameAck: true, FrameHeartbeat: true, FrameClose: true},
	DirF2S: {FrameData: true, FrameResize: true, FrameAck: true, FrameHeartbeat: true, FrameClose: true},
	DirS2F: {FrameData: true, FrameAck: true, FrameHeartbeat: true, FrameClose: true},
}

// windowed reports whether frames of type t count against the window and
// must be Consumed.
func (t FrameType) windowed() bool { return t == FrameData || t == FrameResize }

// Close reasons: fixed codes, shown to the user and written to the audit
// log. A CLOSE frame naming anything else fails the stream.
const (
	CloseExit           = "exit"
	CloseClientClose    = "client-close"
	CloseIdle           = "idle"
	CloseMaxDuration    = "max-duration"
	ClosePeerLost       = "peer-lost"
	CloseIntegrity      = "integrity"
	CloseRevoked        = "revoked"
	CloseKeySevered     = "key-severed"
	CloseFarmerShutdown = "farmer-shutdown"
	CloseSpawnFailed    = "spawn-failed"
	// CloseSproutShutdown: the sprout process is stopping (not in the
	// design's list; added so a graceful sprout stop isn't reported as
	// peer-lost).
	CloseSproutShutdown = "sprout-shutdown"
	// The sprout's policy refusals, which farmer passes on to the CLI as
	// the reason it closes leg 1 with.
	CloseShellDisabled   = "shell-disabled"
	CloseShellNotAllowed = "shell-not-allowed"
	CloseTooManySessions = "too-many-sessions"
	CloseUnsupported     = "unsupported"
	// Farmer couldn't start leg 2: the sprout didn't answer, answered with
	// an Imas-Payload-Error code, or answered in plaintext (a build older
	// than sealed shell, or a bus attempting a downgrade).
	CloseSproutUnreachable = "sprout-unreachable"
	CloseSproutRefused     = "sprout-refused"
	CloseSproutNeedsUpdate = "sprout-needs-upgrade"
)

var closeReasons = map[string]bool{
	CloseExit: true, CloseClientClose: true, CloseIdle: true, CloseMaxDuration: true,
	ClosePeerLost: true, CloseIntegrity: true, CloseRevoked: true, CloseKeySevered: true,
	CloseFarmerShutdown: true, CloseSpawnFailed: true, CloseSproutShutdown: true, CloseShellDisabled: true,
	CloseShellNotAllowed: true, CloseTooManySessions: true, CloseUnsupported: true,
	CloseSproutUnreachable: true, CloseSproutRefused: true, CloseSproutNeedsUpdate: true,
}

// IsCloseReason reports whether reason is one of the fixed close codes.
func IsCloseReason(reason string) bool { return closeReasons[reason] }

// Limits and defaults.
const (
	// MaxFrameData is the most plaintext one DATA frame carries.
	MaxFrameData = 16 << 10
	// MaxStreamFrames is how many frames one direction may send. No real
	// session gets near it; a sender stops there (ErrStreamExhausted).
	MaxStreamFrames = 1 << 32
	// MinTerminalSize and MaxTerminalSize bound HELLO's and RESIZE's
	// columns and rows.
	MinTerminalSize = 1
	MaxTerminalSize = 1000

	DefaultStreamWindow           = 512 << 10
	DefaultStreamMaxUnackedFrames = 256
	DefaultStreamAckBytes         = 64 << 10
	DefaultStreamAckInterval      = 250 * time.Millisecond
	DefaultStreamHeartbeat        = 15 * time.Second
	DefaultStreamPeerTimeout      = 45 * time.Second

	frameHeaderLen  = 1 + 8
	maxFrameWireLen = frameHeaderLen + 1 + MaxFrameData + chacha20poly1305.Overhead
	minFrameWireLen = frameHeaderLen + 1 + chacha20poly1305.Overhead
	maxCloseReason  = 64
)

var (
	// ErrStreamIntegrity: a frame was out of sequence, didn't open, or
	// broke the protocol. The stream is finished.
	ErrStreamIntegrity = errors.New("payloadbox: shell stream integrity failure")
	// ErrStreamPeerLost: nothing arrived for PeerTimeout.
	ErrStreamPeerLost = errors.New("payloadbox: shell stream peer lost")
	// ErrStreamClosed: the stream was closed (Close, or a CLOSE received).
	ErrStreamClosed = errors.New("payloadbox: shell stream closed")
	// ErrStreamExhausted: the direction used up MaxStreamFrames.
	ErrStreamExhausted = errors.New("payloadbox: shell stream frame limit reached")
)

// NewEphemeralKey returns a fresh X25519 key for one leg of one session.
func NewEphemeralKey() (*ecdh.PrivateKey, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("payloadbox: generating ephemeral key: %w", err)
	}
	return k, nil
}

// StreamTranscript is what both ends of a leg hash into the key schedule's
// salt: everything that identifies the leg, so keys derived for one
// session, leg, tenant, sprout or user can never be those of another.
type StreamTranscript struct {
	Leg       string
	TenantID  string
	SproutID  string
	UserID    string
	SessionID string
	// InitiatorEph and ResponderEph are the two ephemeral public keys:
	// the CLI's and farmer's on LegCLI, farmer's and the sprout's on
	// LegSprout.
	InitiatorEph []byte
	ResponderEph []byte
}

func (t StreamTranscript) valid() bool {
	if t.Leg != LegCLI && t.Leg != LegSprout {
		return false
	}
	if t.TenantID == "" || t.SproutID == "" || t.UserID == "" || t.SessionID == "" {
		return false
	}
	return len(t.InitiatorEph) == 32 && len(t.ResponderEph) == 32 && string(t.InitiatorEph) != string(t.ResponderEph)
}

// salt is SHA-256 over a domain tag and every field, each length-prefixed
// so no two transcripts encode alike.
func (t StreamTranscript) salt() []byte {
	h := sha256.New()
	h.Write([]byte("imas-shell-v1 transcript\n"))
	for _, f := range [][]byte{
		[]byte(t.Leg), []byte(t.TenantID), []byte(t.SproutID), []byte(t.UserID), []byte(t.SessionID),
		t.InitiatorEph, t.ResponderEph,
	} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		h.Write(n[:])
		h.Write(f)
	}
	return h.Sum(nil)
}

// directions returns the leg's (initiator->responder, responder->initiator)
// direction labels.
func (t StreamTranscript) directions() (string, string) {
	if t.Leg == LegCLI {
		return DirC2F, DirF2C
	}
	return DirF2S, DirS2F
}

// StreamKeys are one leg's two direction keys. Wipe them when the session
// ends.
type StreamKeys struct {
	leg       string
	sessionID string
	i2r, r2i  [32]byte
}

// Wipe zeroes the keys.
func (k *StreamKeys) Wipe() {
	clear(k.i2r[:])
	clear(k.r2i[:])
}

// DeriveStreamKeys runs X25519 between own, this end's ephemeral private
// key, and peerPub, the other end's ephemeral public key from the
// handshake, and derives the leg's direction keys from the result and
// t. own's public half must be the transcript's InitiatorEph or
// ResponderEph and peerPub the other. A low-order or malformed peerPub,
// or an incomplete transcript, is ErrOpen.
func DeriveStreamKeys(own *ecdh.PrivateKey, peerPub []byte, t StreamTranscript) (*StreamKeys, error) {
	if own == nil || !t.valid() || len(peerPub) != 32 {
		return nil, ErrOpen
	}
	ownPub := own.PublicKey().Bytes()
	switch {
	case string(ownPub) == string(t.InitiatorEph) && string(peerPub) == string(t.ResponderEph):
	case string(ownPub) == string(t.ResponderEph) && string(peerPub) == string(t.InitiatorEph):
	default:
		return nil, ErrOpen
	}
	var p [32]byte
	copy(p[:], peerPub)
	if CheckPublicKey(&p) != nil {
		return nil, ErrOpen
	}
	peer, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, ErrOpen
	}
	secret, err := own.ECDH(peer)
	if err != nil {
		return nil, ErrOpen
	}
	defer clear(secret)
	salt := t.salt()
	k := &StreamKeys{leg: t.Leg, sessionID: t.SessionID}
	i2r, r2i := t.directions()
	for _, d := range []struct {
		dir string
		out *[32]byte
	}{{i2r, &k.i2r}, {r2i, &k.r2i}} {
		key, err := hkdf.Key(sha256.New, secret, salt, "imas-shell-v1 key "+d.dir, 32)
		if err != nil {
			return nil, fmt.Errorf("payloadbox: deriving shell stream key: %w", err)
		}
		copy(d.out[:], key)
		clear(key)
	}
	return k, nil
}

// StreamOptions tunes a Stream; zero fields take the defaults.
type StreamOptions struct {
	Window            int
	MaxUnackedFrames  int
	AckBytes          int
	AckInterval       time.Duration
	HeartbeatInterval time.Duration
	PeerTimeout       time.Duration
}

func (o StreamOptions) withDefaults() StreamOptions {
	if o.Window <= 0 {
		o.Window = DefaultStreamWindow
	}
	if o.MaxUnackedFrames <= 0 {
		o.MaxUnackedFrames = DefaultStreamMaxUnackedFrames
	}
	if o.AckBytes <= 0 {
		o.AckBytes = DefaultStreamAckBytes
	}
	if o.AckInterval <= 0 {
		o.AckInterval = DefaultStreamAckInterval
	}
	if o.HeartbeatInterval <= 0 {
		o.HeartbeatInterval = DefaultStreamHeartbeat
	}
	if o.PeerTimeout <= 0 {
		o.PeerTimeout = DefaultStreamPeerTimeout
	}
	return o
}

// Frame is a frame the stream hands its owner: HELLO, READY, DATA, RESIZE
// or CLOSE. ACK and HEARTBEAT are handled inside the stream.
type Frame struct {
	Type    FrameType
	Seq     uint64
	Payload []byte
}

// CloseInfo is a CLOSE frame's payload.
type CloseInfo struct {
	Reason   string
	ExitCode int32
}

// Stream is one end of one leg: it seals what this end sends and opens
// what it receives, in order, and runs flow control and liveness.
type Stream struct {
	sessionID        string
	sendDir, recvDir string
	send, recv       cipher.AEAD
	publish          func([]byte) error
	opts             StreamOptions

	frames chan Frame
	done   chan struct{}
	notify chan struct{} // a window may have opened

	sendMu   sync.Mutex // serialises sealing and publishing, so seq order is publish order
	nextSend uint64
	sentAt   time.Time
	closed   bool // CLOSE sent
	// sent mirrors nextSend for the receive side, which must not take
	// sendMu while holding mu (sendFrame takes them the other way round).
	sent atomic.Uint64

	mu            sync.Mutex
	err           error
	pending       []pendingFrame // windowed frames sent, not yet acknowledged
	pendingBytes  int
	acked         uint64 // highest ACK value received
	nextRecv      uint64
	recvAt        time.Time
	recvClosed    bool
	unconsumed    []uint64 // seqs of windowed frames delivered, not consumed
	consumedSince int      // bytes consumed since the last ACK sent
	ackSent       uint64

	statsMu                                      sync.Mutex
	sentFrames, sentBytes, recvFrames, recvBytes uint64
}

type pendingFrame struct {
	seq   uint64
	bytes int
}

// NewStream returns this end of a leg whose keys are k. initiator says
// which end this is (see StreamTranscript); publish sends one sealed frame
// to the peer.
func NewStream(k *StreamKeys, initiator bool, publish func([]byte) error, opts StreamOptions) (*Stream, error) {
	if k == nil || publish == nil {
		return nil, errors.New("payloadbox: a stream needs its keys and a publisher")
	}
	i2rDir, r2iDir := StreamTranscript{Leg: k.leg}.directions()
	sendKey, recvKey, sendDir, recvDir := k.i2r, k.r2i, i2rDir, r2iDir
	if !initiator {
		sendKey, recvKey, sendDir, recvDir = k.r2i, k.i2r, r2iDir, i2rDir
	}
	send, err := chacha20poly1305.New(sendKey[:])
	if err != nil {
		return nil, err
	}
	recv, err := chacha20poly1305.New(recvKey[:])
	if err != nil {
		return nil, err
	}
	opts = opts.withDefaults()
	now := time.Now()
	return &Stream{
		sessionID: k.sessionID, sendDir: sendDir, recvDir: recvDir, send: send, recv: recv,
		publish: publish, opts: opts,
		frames: make(chan Frame, opts.MaxUnackedFrames+8),
		done:   make(chan struct{}), notify: make(chan struct{}, 1),
		sentAt: now, recvAt: now,
	}, nil
}

// SendDir and RecvDir are this end's direction labels.
func (s *Stream) SendDir() string { return s.sendDir }
func (s *Stream) RecvDir() string { return s.recvDir }

// Frames delivers, in order, every HELLO, READY, DATA, RESIZE and CLOSE
// frame that opened. Each DATA and RESIZE frame must be passed to
// Consumed once handled.
func (s *Stream) Frames() <-chan Frame { return s.frames }

// Done is closed once the stream failed or was closed; Err says why.
func (s *Stream) Done() <-chan struct{} { return s.done }

// Err is nil while the stream runs, then ErrStreamIntegrity,
// ErrStreamPeerLost, ErrStreamClosed or ErrStreamExhausted.
func (s *Stream) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Stream) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failLocked(err)
}

func (s *Stream) failLocked(err error) {
	if s.err != nil {
		return
	}
	s.err = err
	close(s.done)
}

// Stats are the frames and plaintext bytes this end sent and received.
type StreamStats struct {
	SentFrames, SentBytes, RecvFrames, RecvBytes uint64
}

// Stats returns the stream's counters.
func (s *Stream) Stats() StreamStats {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	return StreamStats{SentFrames: s.sentFrames, SentBytes: s.sentBytes, RecvFrames: s.recvFrames, RecvBytes: s.recvBytes}
}

// additionalData binds a frame to the protocol, its direction, its
// session, its version and its seq.
func additionalData(dir, sessionID string, version byte, seq uint64) []byte {
	ad := make([]byte, 0, 16+2+len(dir)+2+len(sessionID)+1+8)
	ad = append(ad, "imas-shell-v1"...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(dir)))
	ad = append(ad, dir...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(sessionID)))
	ad = append(ad, sessionID...)
	ad = append(ad, version)
	return binary.BigEndian.AppendUint64(ad, seq)
}

func frameNonce(seq uint64) []byte {
	var n [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(n[4:], seq)
	return n[:]
}

// sendFrame seals and publishes one frame. A non-nil closeInfo makes it
// the CLOSE frame, whose payload is built here so the frame count it
// carries is exactly its own seq. Nothing is sent after CLOSE.
func (s *Stream) sendFrame(typ FrameType, payload []byte, closeInfo *CloseInfo) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.closed {
		return ErrStreamClosed
	}
	if s.nextSend >= MaxStreamFrames {
		return ErrStreamExhausted
	}
	seq := s.nextSend
	if closeInfo != nil {
		typ = FrameClose
		payload = make([]byte, 0, 1+len(closeInfo.Reason)+4+8)
		payload = append(payload, byte(len(closeInfo.Reason)))
		payload = append(payload, closeInfo.Reason...)
		payload = binary.BigEndian.AppendUint32(payload, uint32(closeInfo.ExitCode))
		payload = binary.BigEndian.AppendUint64(payload, seq)
	}
	if typ.windowed() {
		s.mu.Lock()
		s.pending = append(s.pending, pendingFrame{seq: seq, bytes: len(payload)})
		s.pendingBytes += len(payload)
		s.mu.Unlock()
	}
	frame := make([]byte, frameHeaderLen, frameHeaderLen+1+len(payload)+chacha20poly1305.Overhead)
	frame[0] = StreamVersion
	binary.BigEndian.PutUint64(frame[1:], seq)
	plaintext := make([]byte, 0, 1+len(payload))
	plaintext = append(plaintext, byte(typ))
	plaintext = append(plaintext, payload...)
	frame = s.send.Seal(frame, frameNonce(seq), plaintext, additionalData(s.sendDir, s.sessionID, StreamVersion, seq))
	clear(plaintext)
	s.nextSend++
	s.sent.Store(s.nextSend)
	if closeInfo != nil {
		s.closed = true
	}
	s.sentAt = time.Now()
	if err := s.publish(frame); err != nil {
		// A frame whose seq was used but which may not have left would
		// leave a gap the peer can never get past: the stream is over.
		s.fail(ErrStreamPeerLost)
		return err
	}
	s.statsMu.Lock()
	s.sentFrames++
	if typ == FrameData {
		s.sentBytes += uint64(len(payload))
	}
	s.statsMu.Unlock()
	return nil
}

// waitWindow blocks until a windowed frame of n bytes fits, ctx ends or
// the stream is done.
func (s *Stream) waitWindow(ctx context.Context, n int) error {
	for {
		s.mu.Lock()
		err := s.err
		fits := len(s.pending) < s.opts.MaxUnackedFrames && (s.pendingBytes == 0 || s.pendingBytes+n <= s.opts.Window)
		s.mu.Unlock()
		if err != nil {
			return err
		}
		if fits {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done:
		case <-s.notify:
		}
	}
}

// SendData sends p as DATA frames of at most MaxFrameData bytes each,
// waiting for the window as needed.
func (s *Stream) SendData(ctx context.Context, p []byte) error {
	for len(p) > 0 {
		n := min(len(p), MaxFrameData)
		if err := s.waitWindow(ctx, n); err != nil {
			return err
		}
		if err := s.sendFrame(FrameData, p[:n], nil); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

// SendResize sends a RESIZE frame, waiting for the window as needed.
func (s *Stream) SendResize(ctx context.Context, cols, rows int) error {
	payload, err := EncodeTerminalSize(cols, rows)
	if err != nil {
		return err
	}
	if err := s.waitWindow(ctx, len(payload)); err != nil {
		return err
	}
	return s.sendFrame(FrameResize, payload, nil)
}

// SendHello sends the CLI's HELLO (seq 0 on c2f).
func (s *Stream) SendHello(cols, rows int) error {
	payload, err := EncodeTerminalSize(cols, rows)
	if err != nil {
		return err
	}
	return s.sendFrame(FrameHello, payload, nil)
}

// SendReady sends farmer's READY (seq 0 on f2c).
func (s *Stream) SendReady() error { return s.sendFrame(FrameReady, nil, nil) }

// Close sends CLOSE, once; later calls do nothing. It works even after
// the stream failed on receive (to tell the peer why), and finishes the
// stream (ErrStreamClosed) if it hadn't failed.
func (s *Stream) Close(info CloseInfo) error {
	if !IsCloseReason(info.Reason) {
		return fmt.Errorf("payloadbox: unknown close reason %q", info.Reason)
	}
	err := s.sendFrame(FrameClose, nil, &info)
	if errors.Is(err, ErrStreamClosed) {
		err = nil
	}
	s.fail(ErrStreamClosed)
	return err
}

// Deliver opens frame, the next message on the leg's receive subject. It
// never blocks. A frame that is out of sequence, doesn't open or breaks
// the protocol fails the stream (ErrStreamIntegrity); frames after that,
// or after a CLOSE, are ignored. It returns the stream's error, if any.
func (s *Stream) Deliver(frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil && !errors.Is(s.err, ErrStreamClosed) {
		return s.err
	}
	if s.recvClosed {
		return nil
	}
	if err := s.deliverLocked(frame); err != nil {
		s.failLocked(ErrStreamIntegrity)
		return ErrStreamIntegrity
	}
	return nil
}

func (s *Stream) deliverLocked(frame []byte) error {
	if len(frame) < minFrameWireLen || len(frame) > maxFrameWireLen || frame[0] != StreamVersion {
		return ErrStreamIntegrity
	}
	seq := binary.BigEndian.Uint64(frame[1:frameHeaderLen])
	if seq != s.nextRecv {
		return ErrStreamIntegrity
	}
	plaintext, err := s.recv.Open(nil, frameNonce(seq), frame[frameHeaderLen:], additionalData(s.recvDir, s.sessionID, frame[0], seq))
	if err != nil || len(plaintext) == 0 {
		return ErrStreamIntegrity
	}
	typ, payload := FrameType(plaintext[0]), plaintext[1:]
	if !allowedFrames[s.recvDir][typ] {
		return ErrStreamIntegrity
	}
	// Key confirmation: the CLI's first frame is HELLO, and farmer's first
	// frame to the CLI is READY or, if leg 2 never came up, CLOSE.
	if seq == 0 && (s.recvDir == DirC2F && typ != FrameHello || s.recvDir == DirF2C && typ != FrameReady && typ != FrameClose) {
		return ErrStreamIntegrity
	}
	switch typ {
	case FrameHello, FrameResize:
		if _, _, err := DecodeTerminalSize(payload); err != nil {
			return ErrStreamIntegrity
		}
		if typ == FrameHello && seq != 0 {
			return ErrStreamIntegrity
		}
	case FrameReady:
		if seq != 0 || len(payload) != 0 {
			return ErrStreamIntegrity
		}
	case FrameData:
		if len(payload) == 0 || len(payload) > MaxFrameData {
			return ErrStreamIntegrity
		}
	case FrameAck:
		if len(payload) != 8 {
			return ErrStreamIntegrity
		}
		if err := s.ackLocked(binary.BigEndian.Uint64(payload)); err != nil {
			return err
		}
	case FrameHeartbeat:
		if len(payload) != 0 {
			return ErrStreamIntegrity
		}
	case FrameClose:
		if _, frames, err := decodeClose(payload); err != nil || frames != seq {
			return ErrStreamIntegrity
		}
	default:
		return ErrStreamIntegrity
	}
	if typ.windowed() {
		// The peer must respect the window; a frame beyond it would only
		// queue without bound.
		if len(s.unconsumed) >= s.opts.MaxUnackedFrames {
			return ErrStreamIntegrity
		}
		s.unconsumed = append(s.unconsumed, seq)
	}
	s.nextRecv++
	s.recvAt = time.Now()
	s.statsMu.Lock()
	s.recvFrames++
	if typ == FrameData {
		s.recvBytes += uint64(len(payload))
	}
	s.statsMu.Unlock()
	if typ == FrameAck || typ == FrameHeartbeat {
		return nil
	}
	if typ == FrameClose {
		s.recvClosed = true
	}
	select {
	case s.frames <- Frame{Type: typ, Seq: seq, Payload: payload}:
	default:
		// Can't happen while the window holds (the channel has room for
		// every windowed frame plus the one-shot ones).
		return ErrStreamIntegrity
	}
	return nil
}

// ackLocked applies an ACK of n: every frame below seq n was consumed.
func (s *Stream) ackLocked(n uint64) error {
	if n < s.acked || n > s.sent.Load() {
		return ErrStreamIntegrity
	}
	s.acked = n
	i := 0
	for i < len(s.pending) && s.pending[i].seq < n {
		s.pendingBytes -= s.pending[i].bytes
		i++
	}
	s.pending = s.pending[i:]
	select {
	case s.notify <- struct{}{}:
	default:
	}
	return nil
}

// Consumed marks the oldest delivered DATA or RESIZE frame handled, so
// the peer may send more. An ACK goes out at once when enough has been
// consumed, otherwise on Run's next tick.
func (s *Stream) Consumed(f Frame) {
	s.mu.Lock()
	if len(s.unconsumed) == 0 || s.unconsumed[0] != f.Seq {
		s.mu.Unlock()
		return
	}
	s.unconsumed = s.unconsumed[1:]
	s.consumedSince += len(f.Payload)
	due := s.consumedSince >= s.opts.AckBytes || s.ackValueLocked()-s.ackSent >= uint64(s.opts.MaxUnackedFrames/2)
	s.mu.Unlock()
	if due {
		s.sendAck()
	}
}

// ackValueLocked is the ACK this end can send: every frame below it was
// received and, if windowed, consumed.
func (s *Stream) ackValueLocked() uint64 {
	if len(s.unconsumed) > 0 {
		return s.unconsumed[0]
	}
	return s.nextRecv
}

// sendAck sends an ACK if it would acknowledge anything new.
func (s *Stream) sendAck() {
	s.mu.Lock()
	n := s.ackValueLocked()
	if n <= s.ackSent || s.err != nil && !errors.Is(s.err, ErrStreamClosed) {
		s.mu.Unlock()
		return
	}
	s.ackSent = n
	s.consumedSince = 0
	s.mu.Unlock()
	var p [8]byte
	binary.BigEndian.PutUint64(p[:], n)
	_ = s.sendFrame(FrameAck, p[:], nil)
}

// Run keeps the stream alive until ctx ends or the stream is done: it
// sends ACKs for consumed frames every AckInterval, a HEARTBEAT after
// HeartbeatInterval without sending, and fails the stream with
// ErrStreamPeerLost after PeerTimeout without receiving. It returns the
// stream's error, or ctx's.
func (s *Stream) Run(ctx context.Context) error {
	t := time.NewTicker(s.opts.AckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.done:
			return s.Err()
		case now := <-t.C:
			s.sendAck()
			s.mu.Lock()
			lost := now.Sub(s.recvAt) >= s.opts.PeerTimeout && !s.recvClosed
			s.mu.Unlock()
			if lost {
				s.fail(ErrStreamPeerLost)
				return ErrStreamPeerLost
			}
			s.sendMu.Lock()
			idle := now.Sub(s.sentAt) >= s.opts.HeartbeatInterval && !s.closed
			s.sendMu.Unlock()
			if idle {
				_ = s.sendFrame(FrameHeartbeat, nil, nil)
			}
		}
	}
}

// EncodeTerminalSize is HELLO's and RESIZE's payload: columns and rows,
// uint16 each, each within MinTerminalSize..MaxTerminalSize.
func EncodeTerminalSize(cols, rows int) ([]byte, error) {
	if cols < MinTerminalSize || cols > MaxTerminalSize || rows < MinTerminalSize || rows > MaxTerminalSize {
		return nil, fmt.Errorf("payloadbox: terminal size %dx%d is outside %d..%d", cols, rows, MinTerminalSize, MaxTerminalSize)
	}
	p := make([]byte, 4)
	binary.BigEndian.PutUint16(p, uint16(cols))
	binary.BigEndian.PutUint16(p[2:], uint16(rows))
	return p, nil
}

// DecodeTerminalSize reads EncodeTerminalSize's payload.
func DecodeTerminalSize(p []byte) (cols, rows int, err error) {
	if len(p) != 4 {
		return 0, 0, errors.New("payloadbox: bad terminal size")
	}
	cols, rows = int(binary.BigEndian.Uint16(p)), int(binary.BigEndian.Uint16(p[2:]))
	if cols < MinTerminalSize || cols > MaxTerminalSize || rows < MinTerminalSize || rows > MaxTerminalSize {
		return 0, 0, errors.New("payloadbox: terminal size out of bounds")
	}
	return cols, rows, nil
}

// DecodeClose reads a CLOSE frame's payload.
func DecodeClose(p []byte) (CloseInfo, error) {
	info, _, err := decodeClose(p)
	return info, err
}

func decodeClose(p []byte) (CloseInfo, uint64, error) {
	if len(p) < 1 {
		return CloseInfo{}, 0, ErrStreamIntegrity
	}
	n := int(p[0])
	if n == 0 || n > maxCloseReason || len(p) != 1+n+4+8 {
		return CloseInfo{}, 0, ErrStreamIntegrity
	}
	reason := string(p[1 : 1+n])
	if !IsCloseReason(reason) {
		return CloseInfo{}, 0, ErrStreamIntegrity
	}
	exit := int32(binary.BigEndian.Uint32(p[1+n:]))
	frames := binary.BigEndian.Uint64(p[1+n+4:])
	return CloseInfo{Reason: reason, ExitCode: exit}, frames, nil
}
