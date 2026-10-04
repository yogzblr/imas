package shell

// The imas CLI's end of sealed shell (leg 1). FLAG FOR SECURITY REVIEW.
//
// The CLI holds no tenant private key. It authenticates with its own
// registered CLI box key: the open is a sealed control-plane request
// (c2f.shell.open), which only the holder of that key could have made and
// only farmer can open, and its reply opens only under the tenant key the
// CLI pins from explicit config (tenantboxpub). The open carries a fresh
// ephemeral key; the reply carries farmer's. The CLI then proves it holds
// its ephemeral key with HELLO (seq 0), and farmer contacts the sprout
// only after that, so a captured open replayed by the bus spawns nothing.
// Everything after is a payloadbox.Stream that only this CLI and farmer
// can read.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/payloadbox"
)

// DefaultReadyTimeout bounds the wait for farmer's READY after HELLO:
// farmer's start to the sprout takes at most StartTimeout.
const DefaultReadyTimeout = StartTimeout + 10*time.Second

// ClientOptions is everything RunClient needs.
type ClientOptions struct {
	NC *nats.Conn
	// Open sends the sealed c2f.shell.open request (the CLI's
	// client.SealedRequest with payloadbox.PurposeShellOpen and method
	// "shell.open") and returns the opened result. It is never sent in
	// plaintext, and a reply that isn't sealed to this CLI is an error.
	Open func(OpenRequest) (json.RawMessage, error)
	// TenantID and UserID are the CLI's pinned tenant and its user ID
	// (NKey public key), as farmer knows them: they go into the key
	// schedule.
	TenantID, UserID string

	SproutID       string
	Shell          string
	IdleTimeoutSec int
	Cols, Rows     int

	Stdin  io.Reader
	Stdout io.Writer
	// Resize, if set, delivers new terminal sizes.
	Resize <-chan [2]int
	// OnReady runs once the remote shell is up (e.g. to put the terminal
	// in raw mode).
	OnReady func(OpenResult)

	Stream       payloadbox.StreamOptions
	ReadyTimeout time.Duration
}

// ClientResult is how a session ended.
type ClientResult struct {
	SessionID string
	// Reason is a payloadbox close code: the one farmer sent, or the one
	// this end closed with (integrity, peer-lost, client-close).
	Reason   string
	ExitCode int
	// Remote is true if farmer sent the CLOSE.
	Remote bool
}

// ErrNotReady: the session was opened but farmer neither confirmed the
// shell nor said why within the ready timeout.
var ErrNotReady = errors.New("shell: farmer didn't confirm the session")

// RunClient opens a shell on o.SproutID and relays it until it ends or
// ctx does (which closes it with client-close).
func RunClient(ctx context.Context, o ClientOptions) (*ClientResult, error) {
	if o.NC == nil || o.Open == nil || o.TenantID == "" || o.UserID == "" || o.Stdin == nil || o.Stdout == nil {
		return nil, errors.New("shell: incomplete client options")
	}
	if !ValidShellPath(o.Shell) {
		return nil, fmt.Errorf("shell: %q is not an absolute path", o.Shell)
	}
	if _, err := payloadbox.EncodeTerminalSize(o.Cols, o.Rows); err != nil {
		return nil, err
	}
	eph, err := payloadbox.NewEphemeralKey()
	if err != nil {
		return nil, err
	}
	ephPub := eph.PublicKey().Bytes()
	raw, err := o.Open(OpenRequest{SproutID: o.SproutID, Shell: o.Shell, IdleTimeoutSec: o.IdleTimeoutSec, CLIEphPub: ephPub})
	if err != nil {
		return nil, err
	}
	var res OpenResult
	if err := json.Unmarshal(raw, &res); err != nil || !ValidSessionID(res.SessionID) || res.SproutID != o.SproutID {
		return nil, errors.New("shell: farmer's answer to the open is malformed")
	}
	keys, err := payloadbox.DeriveStreamKeys(eph, res.FarmerEphPub,
		Transcript(payloadbox.LegCLI, o.TenantID, o.SproutID, o.UserID, res.SessionID, ephPub, res.FarmerEphPub))
	if err != nil {
		return nil, errors.New("shell: farmer's session key is unusable")
	}
	defer keys.Wipe()
	c2f := CLISubject(res.SessionID, payloadbox.DirC2F)
	stream, err := payloadbox.NewStream(keys, true, func(frame []byte) error {
		m := nats.NewMsg(c2f)
		m.Header.Set(payloadbox.Header, payloadbox.HeaderShell1)
		m.Data = frame
		return o.NC.PublishMsg(m)
	}, o.Stream)
	if err != nil {
		return nil, err
	}
	sub, err := o.NC.Subscribe(CLISubject(res.SessionID, payloadbox.DirF2C), func(m *nats.Msg) { _ = stream.Deliver(m.Data) })
	if err != nil {
		return nil, err
	}
	defer func() { _ = sub.Unsubscribe() }()
	if err := o.NC.Flush(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- stream.Run(ctx) }()

	result := &ClientResult{SessionID: res.SessionID}
	closeWith := func(reason string) (*ClientResult, error) {
		_ = stream.Close(payloadbox.CloseInfo{Reason: reason, ExitCode: exitCodeNone})
		result.Reason, result.ExitCode = reason, exitCodeNone
		return result, nil
	}
	if err := stream.SendHello(o.Cols, o.Rows); err != nil {
		return nil, err
	}

	// Wait for READY, or farmer's CLOSE saying why not.
	readyTimeout := o.ReadyTimeout
	if readyTimeout <= 0 {
		readyTimeout = DefaultReadyTimeout
	}
	select {
	case f := <-stream.Frames():
		if f.Type == payloadbox.FrameClose {
			return remoteClose(result, f)
		}
		// READY: the stream refuses anything else at seq 0.
	case <-time.After(readyTimeout):
		_ = stream.Close(payloadbox.CloseInfo{Reason: payloadbox.CloseClientClose, ExitCode: exitCodeNone})
		return nil, ErrNotReady
	case <-stream.Done():
		return closeWith(streamFailure(stream.Err()))
	case <-ctx.Done():
		return closeWith(payloadbox.CloseClientClose)
	}
	if o.OnReady != nil {
		o.OnReady(res)
	}

	go func() {
		buf := make([]byte, payloadbox.MaxFrameData)
		for {
			n, err := o.Stdin.Read(buf)
			if n > 0 {
				if stream.SendData(ctx, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				// End of input stops input; the session runs until the
				// remote shell ends.
				return
			}
		}
	}()
	if o.Resize != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case sz, ok := <-o.Resize:
					if !ok {
						return
					}
					if _, err := payloadbox.EncodeTerminalSize(sz[0], sz[1]); err == nil {
						if stream.SendResize(ctx, sz[0], sz[1]) != nil {
							return
						}
					}
				}
			}
		}()
	}

	for {
		select {
		case f := <-stream.Frames():
			switch f.Type {
			case payloadbox.FrameData:
				_, _ = o.Stdout.Write(f.Payload)
				stream.Consumed(f)
			case payloadbox.FrameClose:
				return remoteClose(result, f)
			}
		case <-stream.Done():
			// Drain what arrived before the stream ended (a CLOSE among it).
		drain:
			for {
				select {
				case f := <-stream.Frames():
					if f.Type == payloadbox.FrameData {
						_, _ = o.Stdout.Write(f.Payload)
					} else if f.Type == payloadbox.FrameClose {
						return remoteClose(result, f)
					}
				default:
					break drain
				}
			}
			return closeWith(streamFailure(stream.Err()))
		case err := <-runErr:
			if errors.Is(err, payloadbox.ErrStreamPeerLost) {
				return closeWith(payloadbox.ClosePeerLost)
			}
		case <-ctx.Done():
			return closeWith(payloadbox.CloseClientClose)
		}
	}
}

func remoteClose(result *ClientResult, f payloadbox.Frame) (*ClientResult, error) {
	info, err := payloadbox.DecodeClose(f.Payload)
	if err != nil {
		return nil, err
	}
	result.Reason, result.ExitCode, result.Remote = info.Reason, int(info.ExitCode), true
	return result, nil
}

func streamFailure(err error) string {
	if errors.Is(err, payloadbox.ErrStreamPeerLost) {
		return payloadbox.ClosePeerLost
	}
	return payloadbox.CloseIntegrity
}
