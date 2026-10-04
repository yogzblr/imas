package payloadbox

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"errors"
	"sync"
	"testing"
	"time"
)

// wire is one direction of a leg in a test: every frame published, kept
// for the test to deliver (or replay, reorder, drop, tamper with).
type wire struct {
	mu     sync.Mutex
	frames [][]byte
}

func (w *wire) publish(f []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.frames = append(w.frames, append([]byte(nil), f...))
	return nil
}

func (w *wire) take() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := w.frames
	w.frames = nil
	return out
}

type testLeg struct {
	init, resp         *Stream
	toResp, toInit     *wire
	initKey, respKey   *ecdh.PrivateKey
	transcript         StreamTranscript
	initKeys, respKeys *StreamKeys
}

func newTestTranscript(t *testing.T, leg string, initPub, respPub []byte) StreamTranscript {
	t.Helper()
	return StreamTranscript{
		Leg: leg, TenantID: "t_1", SproutID: "web-01", UserID: "UALICE", SessionID: "0123456789abcdef0123456789abcdef",
		InitiatorEph: initPub, ResponderEph: respPub,
	}
}

func newTestLeg(t *testing.T, leg string, opts StreamOptions) *testLeg {
	t.Helper()
	ik, err := NewEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	rk, err := NewEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	tr := newTestTranscript(t, leg, ik.PublicKey().Bytes(), rk.PublicKey().Bytes())
	ikeys, err := DeriveStreamKeys(ik, rk.PublicKey().Bytes(), tr)
	if err != nil {
		t.Fatal(err)
	}
	rkeys, err := DeriveStreamKeys(rk, ik.PublicKey().Bytes(), tr)
	if err != nil {
		t.Fatal(err)
	}
	l := &testLeg{toResp: &wire{}, toInit: &wire{}, initKey: ik, respKey: rk, transcript: tr, initKeys: ikeys, respKeys: rkeys}
	if l.init, err = NewStream(ikeys, true, l.toResp.publish, opts); err != nil {
		t.Fatal(err)
	}
	if l.resp, err = NewStream(rkeys, false, l.toInit.publish, opts); err != nil {
		t.Fatal(err)
	}
	return l
}

func deliverAll(t *testing.T, s *Stream, frames [][]byte) {
	t.Helper()
	for _, f := range frames {
		if err := s.Deliver(f); err != nil {
			t.Fatalf("Deliver: %v", err)
		}
	}
}

func nextFrame(t *testing.T, s *Stream) Frame {
	t.Helper()
	select {
	case f := <-s.Frames():
		return f
	case <-time.After(2 * time.Second):
		t.Fatal("no frame")
	}
	return Frame{}
}

func wantIntegrity(t *testing.T, name string, s *Stream, frame []byte) {
	t.Helper()
	if err := s.Deliver(frame); !errors.Is(err, ErrStreamIntegrity) {
		t.Fatalf("%s: Deliver = %v, want ErrStreamIntegrity", name, err)
	}
	if !errors.Is(s.Err(), ErrStreamIntegrity) {
		t.Fatalf("%s: stream error %v, want ErrStreamIntegrity", name, s.Err())
	}
	select {
	case <-s.Done():
	default:
		t.Fatalf("%s: stream not done after an integrity failure", name)
	}
}

func TestDeriveStreamKeysAgreeAndDiffer(t *testing.T) {
	l := newTestLeg(t, LegCLI, StreamOptions{})
	if l.initKeys.i2r != l.respKeys.i2r || l.initKeys.r2i != l.respKeys.r2i {
		t.Fatal("the two ends derived different keys")
	}
	if l.initKeys.i2r == l.initKeys.r2i {
		t.Fatal("both directions share a key")
	}
	// Every transcript field changes the keys.
	for name, mutate := range map[string]func(*StreamTranscript){
		"leg":     func(tr *StreamTranscript) { tr.Leg = LegSprout },
		"tenant":  func(tr *StreamTranscript) { tr.TenantID = "t_2" },
		"sprout":  func(tr *StreamTranscript) { tr.SproutID = "web-02" },
		"user":    func(tr *StreamTranscript) { tr.UserID = "UBOB" },
		"session": func(tr *StreamTranscript) { tr.SessionID = "ffffffffffffffffffffffffffffffff" },
	} {
		tr := l.transcript
		mutate(&tr)
		k, err := DeriveStreamKeys(l.initKey, l.respKey.PublicKey().Bytes(), tr)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if k.i2r == l.initKeys.i2r || k.r2i == l.initKeys.r2i {
			t.Errorf("changing the %s left a key unchanged", name)
		}
	}
}

func TestDeriveStreamKeysRefusesBadInput(t *testing.T) {
	l := newTestLeg(t, LegSprout, StreamOptions{})
	other, _ := NewEphemeralKey()
	lowOrder := make([]byte, 32) // the all-zero point
	for name, c := range map[string]struct {
		own  *ecdh.PrivateKey
		peer []byte
		tr   StreamTranscript
	}{
		"peer not in transcript": {l.initKey, other.PublicKey().Bytes(), l.transcript},
		"own not in transcript":  {other, l.respKey.PublicKey().Bytes(), l.transcript},
		"low-order peer":         {l.initKey, lowOrder, func() StreamTranscript { tr := l.transcript; tr.ResponderEph = lowOrder; return tr }()},
		"short peer":             {l.initKey, []byte{1, 2, 3}, l.transcript},
		"no session":             {l.initKey, l.respKey.PublicKey().Bytes(), func() StreamTranscript { tr := l.transcript; tr.SessionID = ""; return tr }()},
		"unknown leg":            {l.initKey, l.respKey.PublicKey().Bytes(), func() StreamTranscript { tr := l.transcript; tr.Leg = "x"; return tr }()},
		"same key on both sides": {l.initKey, l.initKey.PublicKey().Bytes(), func() StreamTranscript { tr := l.transcript; tr.ResponderEph = tr.InitiatorEph; return tr }()},
		"nil own key":            {nil, l.respKey.PublicKey().Bytes(), l.transcript},
	} {
		if _, err := DeriveStreamKeys(c.own, c.peer, c.tr); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: err = %v, want ErrOpen", name, err)
		}
	}
}

func TestStreamRoundTrip(t *testing.T) {
	l := newTestLeg(t, LegCLI, StreamOptions{})
	ctx := context.Background()
	if err := l.init.SendHello(120, 40); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("x"), MaxFrameData+10)
	if err := l.init.SendData(ctx, big); err != nil {
		t.Fatal(err)
	}
	if err := l.init.SendResize(ctx, 80, 24); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, l.resp, l.toResp.take())

	f := nextFrame(t, l.resp)
	if cols, rows, err := DecodeTerminalSize(f.Payload); f.Type != FrameHello || err != nil || cols != 120 || rows != 40 {
		t.Fatalf("hello %v %dx%d %v", f.Type, cols, rows, err)
	}
	var got []byte
	for range 2 {
		f := nextFrame(t, l.resp)
		if f.Type != FrameData {
			t.Fatalf("got %v, want DATA", f.Type)
		}
		got = append(got, f.Payload...)
		l.resp.Consumed(f)
	}
	if !bytes.Equal(got, big) {
		t.Fatal("data changed in transit")
	}
	if f := nextFrame(t, l.resp); f.Type != FrameResize {
		t.Fatalf("got %v, want RESIZE", f.Type)
	} else {
		l.resp.Consumed(f)
	}

	if err := l.resp.SendReady(); err != nil {
		t.Fatal(err)
	}
	if err := l.resp.Close(CloseInfo{Reason: CloseExit, ExitCode: 3}); err != nil {
		t.Fatal(err)
	}
	// Close is once only.
	if err := l.resp.Close(CloseInfo{Reason: CloseIdle}); err != nil {
		t.Fatal(err)
	}
	frames := l.toInit.take()
	deliverAll(t, l.init, frames)
	if f := nextFrame(t, l.init); f.Type != FrameReady {
		t.Fatalf("got %v, want READY", f.Type)
	}
	f = nextFrame(t, l.init)
	info, err := DecodeClose(f.Payload)
	if f.Type != FrameClose || err != nil || info.Reason != CloseExit || info.ExitCode != 3 {
		t.Fatalf("close %v %+v %v", f.Type, info, err)
	}
	// Anything after CLOSE is ignored.
	if err := l.init.Deliver(frames[0]); err != nil {
		t.Fatalf("frame after CLOSE: %v", err)
	}
	st := l.init.Stats()
	if st.SentFrames != 4 || st.SentBytes != uint64(len(big)) {
		t.Fatalf("stats %+v", st)
	}
}

// Every way a compromised bus can interfere with a frame fails the
// stream: replay, reorder, drop, tamper, reflect, move to another session.
func TestStreamFailsClosed(t *testing.T) {
	type setup func(t *testing.T) (*Stream, []byte)
	sent := func(t *testing.T, n int) (*testLeg, [][]byte) {
		l := newTestLeg(t, LegSprout, StreamOptions{})
		for range n {
			if err := l.init.SendData(context.Background(), []byte("ls\n")); err != nil {
				t.Fatal(err)
			}
		}
		return l, l.toResp.take()
	}
	cases := map[string]setup{
		"replay": func(t *testing.T) (*Stream, []byte) {
			l, fs := sent(t, 2)
			deliverAll(t, l.resp, fs[:2])
			return l.resp, fs[0]
		},
		"duplicate": func(t *testing.T) (*Stream, []byte) {
			l, fs := sent(t, 1)
			deliverAll(t, l.resp, fs)
			return l.resp, fs[0]
		},
		"reorder": func(t *testing.T) (*Stream, []byte) {
			l, fs := sent(t, 2)
			return l.resp, fs[1]
		},
		"drop": func(t *testing.T) (*Stream, []byte) {
			l, fs := sent(t, 3)
			deliverAll(t, l.resp, fs[:1])
			return l.resp, fs[2]
		},
		"tamper ciphertext": func(t *testing.T) (*Stream, []byte) {
			l, fs := sent(t, 1)
			f := fs[0]
			f[len(f)-1] ^= 1
			return l.resp, f
		},
		"tamper seq": func(t *testing.T) (*Stream, []byte) {
			l, fs := sent(t, 2)
			deliverAll(t, l.resp, fs[:1])
			f := append([]byte(nil), fs[0]...)
			f[8] = 1 // claims seq 1 but was sealed as seq 0
			return l.resp, f
		},
		"bad version": func(t *testing.T) (*Stream, []byte) {
			l, fs := sent(t, 1)
			fs[0][0] = 2
			return l.resp, fs[0]
		},
		"truncated": func(t *testing.T) (*Stream, []byte) {
			l, fs := sent(t, 1)
			return l.resp, fs[0][:10]
		},
		"reflected back at its sender": func(t *testing.T) (*Stream, []byte) {
			l, fs := sent(t, 1)
			return l.init, fs[0]
		},
		"another session": func(t *testing.T) (*Stream, []byte) {
			_, fs := sent(t, 1)
			other := newTestLeg(t, LegSprout, StreamOptions{})
			return other.resp, fs[0]
		},
		"garbage": func(t *testing.T) (*Stream, []byte) {
			l := newTestLeg(t, LegSprout, StreamOptions{})
			return l.resp, bytes.Repeat([]byte{1}, 64)
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s, f := c(t)
			wantIntegrity(t, name, s, f)
			// And it stays failed: even a genuine next frame is refused.
			if err := s.Deliver(f); !errors.Is(err, ErrStreamIntegrity) {
				t.Fatalf("after failure: %v", err)
			}
		})
	}
}

// The CLI's first frame must be HELLO (key confirmation), and each
// direction carries only its own frame types.
func TestStreamFrameRules(t *testing.T) {
	l := newTestLeg(t, LegCLI, StreamOptions{})
	if err := l.init.SendData(context.Background(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	wantIntegrity(t, "DATA before HELLO", l.resp, l.toResp.take()[0])

	l = newTestLeg(t, LegCLI, StreamOptions{})
	if err := l.resp.SendData(context.Background(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	wantIntegrity(t, "DATA before READY", l.init, l.toInit.take()[0])

	l = newTestLeg(t, LegSprout, StreamOptions{})
	if err := l.resp.SendResize(context.Background(), 10, 10); err != nil {
		t.Fatal(err)
	}
	wantIntegrity(t, "RESIZE from the sprout", l.init, l.toInit.take()[0])

	l = newTestLeg(t, LegSprout, StreamOptions{})
	if err := l.init.SendHello(10, 10); err != nil {
		t.Fatal(err)
	}
	wantIntegrity(t, "HELLO on leg 2", l.resp, l.toResp.take()[0])

	if _, err := EncodeTerminalSize(0, 10); err == nil {
		t.Error("0 columns encoded")
	}
	if _, err := EncodeTerminalSize(10, 1001); err == nil {
		t.Error("1001 rows encoded")
	}
	if err := newTestLeg(t, LegCLI, StreamOptions{}).init.Close(CloseInfo{Reason: "made-up"}); err == nil {
		t.Error("closed with an unknown reason")
	}
}

// A sender stops at the window and resumes once the receiver consumed
// and acknowledged.
func TestStreamFlowControl(t *testing.T) {
	l := newTestLeg(t, LegSprout, StreamOptions{Window: 4096, MaxUnackedFrames: 4, AckBytes: 1 << 20, AckInterval: time.Hour})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sentAll := make(chan error, 1)
	go func() { sentAll <- l.init.SendData(ctx, bytes.Repeat([]byte("y"), 3*MaxFrameData)) }()

	// Only the first window's worth goes out.
	time.Sleep(100 * time.Millisecond)
	first := l.toResp.take()
	if len(first) != 1 {
		t.Fatalf("%d frames sent before any ACK, want 1 (the window holds one)", len(first))
	}
	select {
	case err := <-sentAll:
		t.Fatalf("SendData returned before the window opened: %v", err)
	default:
	}
	// Delivered but not consumed: no ACK.
	deliverAll(t, l.resp, first)
	l.resp.sendAck()
	if acks := l.toInit.take(); len(acks) != 0 {
		t.Fatalf("ACK sent for an unconsumed frame")
	}
	for range 3 {
		f := nextFrame(t, l.resp)
		l.resp.Consumed(f)
		l.resp.sendAck()
		deliverAll(t, l.init, l.toInit.take())
		time.Sleep(50 * time.Millisecond)
		deliverAll(t, l.resp, l.toResp.take())
	}
	if err := <-sentAll; err != nil {
		t.Fatal(err)
	}
}

// A peer that ignores the window fails the stream instead of queueing
// without bound.
func TestStreamWindowOverrun(t *testing.T) {
	l := newTestLeg(t, LegSprout, StreamOptions{MaxUnackedFrames: 1000})
	small, err := NewStream(l.respKeys, false, l.toInit.publish, StreamOptions{MaxUnackedFrames: 2})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := l.init.SendData(context.Background(), []byte("z")); err != nil {
			t.Fatal(err)
		}
	}
	fs := l.toResp.take()
	deliverAll(t, small, fs[:2])
	wantIntegrity(t, "third unacknowledged frame", small, fs[2])
}

// An ACK for frames never sent is a protocol violation.
func TestStreamBogusAck(t *testing.T) {
	l := newTestLeg(t, LegSprout, StreamOptions{})
	if err := l.init.SendData(context.Background(), []byte("a")); err != nil {
		t.Fatal(err)
	}
	deliverAll(t, l.resp, l.toResp.take())
	f := nextFrame(t, l.resp)
	l.resp.Consumed(f)
	// Forge an over-acknowledgement by sealing with the responder's own
	// stream: an ACK of 5 when one frame was sent.
	var p [8]byte
	p[7] = 5
	if err := l.resp.sendFrame(FrameAck, p[:], nil); err != nil {
		t.Fatal(err)
	}
	wantIntegrity(t, "ACK beyond what was sent", l.init, l.toInit.take()[0])
}

func TestStreamHeartbeatAndPeerLost(t *testing.T) {
	l := newTestLeg(t, LegSprout, StreamOptions{AckInterval: 10 * time.Millisecond, HeartbeatInterval: 30 * time.Millisecond, PeerTimeout: 200 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.init.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	hb := l.toResp.take()
	if len(hb) == 0 {
		t.Fatal("no heartbeat sent")
	}
	// Heartbeats keep the receiver alive and reach nobody's queue.
	deliverAll(t, l.resp, hb)
	select {
	case f := <-l.resp.Frames():
		t.Fatalf("heartbeat surfaced as %v", f.Type)
	default:
	}
	// The initiator hears nothing back: peer lost.
	select {
	case err := <-done:
		if !errors.Is(err, ErrStreamPeerLost) || !errors.Is(l.init.Err(), ErrStreamPeerLost) {
			t.Fatalf("Run = %v, Err = %v", err, l.init.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("peer never declared lost")
	}
}

func TestCloseCarriesFrameCount(t *testing.T) {
	l := newTestLeg(t, LegSprout, StreamOptions{})
	if err := l.init.SendData(context.Background(), []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := l.init.Close(CloseInfo{Reason: CloseRevoked}); err != nil {
		t.Fatal(err)
	}
	if err := l.init.SendData(context.Background(), []byte("b")); err == nil {
		t.Fatal("sent after CLOSE")
	}
	fs := l.toResp.take()
	if len(fs) != 2 {
		t.Fatalf("%d frames", len(fs))
	}
	deliverAll(t, l.resp, fs)
	nextFrame(t, l.resp)
	f := nextFrame(t, l.resp)
	if info, err := DecodeClose(f.Payload); err != nil || info.Reason != CloseRevoked {
		t.Fatalf("%+v %v", info, err)
	}
	if !errors.Is(l.init.Err(), ErrStreamClosed) {
		t.Fatalf("closer's Err = %v", l.init.Err())
	}
}
