package natskeys

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/yogzblr/imas/internal/openbao"
)

// The sign dispatcher: one per store. Workers goroutines each take a
// queued sign, drain up to batchMax-1 more that are already waiting, and
// send them grouped by key, so many concurrent signs (a tenant's sprout
// resync) cost few requests. One caller alone goes out as a plain
// "input"; two or more for the same key as "batch_input".

// groupKey is what signs are batched by. The public key is part of it:
// a key deleted and created again restarts at version 1 with a new key,
// and a pair loaded before that must not share a batch (and so a local
// verification key) with one loaded after.
type groupKey struct {
	name    string
	version int
	pub     string
}

type signResult struct {
	sig []byte
	err error
}

type signJob struct {
	ctx   context.Context
	key   groupKey
	pub   ed25519.PublicKey
	input []byte
	done  chan signResult // buffered 1; written once
}

type dispatcher struct {
	queue    chan *signJob
	batchMax int
	send     func(ctx context.Context, key groupKey, jobs []*signJob)

	ctx    context.Context // cancelled by close: aborts requests in flight
	cancel context.CancelFunc
	closed chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
}

func newDispatcher(workers, batchMax int, send func(context.Context, groupKey, []*signJob)) *dispatcher {
	ctx, cancel := context.WithCancel(context.Background())
	d := &dispatcher{
		queue:    make(chan *signJob, workers*batchMax),
		batchMax: batchMax,
		send:     send,
		ctx:      ctx,
		cancel:   cancel,
		closed:   make(chan struct{}),
	}
	d.wg.Add(workers)
	for range workers {
		go d.work()
	}
	return d
}

func (d *dispatcher) close() {
	d.once.Do(func() {
		close(d.closed)
		d.cancel()
		d.wg.Wait()
	})
}

// submit queues j and waits for its result, j.ctx's end, or close.
func (d *dispatcher) submit(ctx context.Context, j *signJob) ([]byte, error) {
	select {
	case <-d.closed:
		return nil, ErrClosed
	default:
	}
	select {
	case d.queue <- j:
	case <-d.closed:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctxError(ctx.Err())
	}
	select {
	case r := <-j.done:
		return r.sig, r.err
	case <-ctx.Done():
		return nil, ctxError(ctx.Err())
	case <-d.closed:
		// A result that raced the close still counts.
		select {
		case r := <-j.done:
			return r.sig, r.err
		default:
			return nil, ErrClosed
		}
	}
}

func (d *dispatcher) work() {
	defer d.wg.Done()
	for {
		select {
		case <-d.closed:
			return
		case j := <-d.queue:
			batch := []*signJob{j}
		drain:
			for len(batch) < d.batchMax {
				select {
				case j := <-d.queue:
					batch = append(batch, j)
				default:
					break drain
				}
			}
			d.dispatch(batch)
		}
	}
}

// dispatch groups batch by key, in first-seen order, and sends each
// group, skipping callers that have already gone.
func (d *dispatcher) dispatch(batch []*signJob) {
	var order []groupKey
	groups := map[groupKey][]*signJob{}
	for _, j := range batch {
		if j.ctx.Err() != nil {
			j.done <- signResult{err: ctxError(j.ctx.Err())}
			continue
		}
		if _, ok := groups[j.key]; !ok {
			order = append(order, j.key)
		}
		groups[j.key] = append(groups[j.key], j)
	}
	for _, k := range order {
		select {
		case <-d.closed:
			for _, j := range groups[k] {
				j.done <- signResult{err: ErrClosed}
			}
			continue
		default:
		}
		ctx, cancel := groupContext(d.ctx, groups[k])
		d.send(ctx, k, groups[k])
		cancel()
	}
}

// groupContext is parent, also cancelled once every job's caller has
// gone, so a worker doesn't spend its retries on signs nobody waits for.
func groupContext(parent context.Context, jobs []*signJob) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	remaining := atomic.Int64{}
	remaining.Store(int64(len(jobs)))
	stops := make([]func() bool, len(jobs))
	for i, j := range jobs {
		stops[i] = context.AfterFunc(j.ctx, func() {
			if remaining.Add(-1) == 0 {
				cancel()
			}
		})
	}
	return ctx, func() {
		for _, stop := range stops {
			stop()
		}
		cancel()
	}
}

// signGroup sends one sign request for jobs (all the same key and
// version) and delivers each job's result. An HTTP-level failure fails
// every job; a batch item's error fails only its job.
func (s *TransitKeyStore) signGroup(ctx context.Context, key groupKey, jobs []*signJob) {
	fail := func(err error) {
		for _, j := range jobs {
			j.done <- signResult{err: err}
		}
	}
	body := map[string]any{"key_version": key.version}
	if len(jobs) == 1 {
		body["input"] = base64.StdEncoding.EncodeToString(jobs[0].input)
	} else {
		items := make([]map[string]string, len(jobs))
		for i, j := range jobs {
			items[i] = map[string]string{
				"input":     base64.StdEncoding.EncodeToString(j.input),
				"reference": strconv.Itoa(i),
			}
		}
		body["batch_input"] = items
	}
	var data struct {
		Signature    string `json:"signature"`
		BatchResults []struct {
			Signature string `json:"signature"`
			Error     string `json:"error"`
			Reference string `json:"reference"`
		} `json:"batch_results"`
	}
	_, err := s.call(ctx, func(ctx context.Context) error {
		secret, err := s.ob.Post(ctx, s.mount+"/sign/"+key.name, body)
		if err != nil {
			return err
		}
		return openbao.DecodeData(secret, &data)
	})
	if err != nil {
		if ctx.Err() != nil {
			// Closed, or every caller has gone (they read nothing).
			fail(ErrClosed)
			return
		}
		fail(fmt.Errorf("%w: %s: %w", ErrSignFailed, key.name, err))
		return
	}
	if len(jobs) == 1 {
		sig, err := checkSignature(key, jobs[0], data.Signature)
		jobs[0].done <- signResult{sig: sig, err: err}
		return
	}
	if len(data.BatchResults) != len(jobs) {
		fail(fmt.Errorf("%w: %s: %d batch results for %d inputs", ErrSignFailed, key.name, len(data.BatchResults), len(jobs)))
		return
	}
	for i, r := range data.BatchResults {
		// Results come back in input order; a reference, when echoed,
		// must agree.
		if r.Reference != "" && r.Reference != strconv.Itoa(i) {
			fail(fmt.Errorf("%w: %s: batch result %d has reference %q", ErrSignFailed, key.name, i, r.Reference))
			return
		}
	}
	for i, r := range data.BatchResults {
		if r.Error != "" {
			jobs[i].done <- signResult{err: fmt.Errorf("%w: %s: %s", ErrSignFailed, key.name, r.Error)}
			continue
		}
		sig, err := checkSignature(key, jobs[i], r.Signature)
		jobs[i].done <- signResult{sig: sig, err: err}
	}
}

// checkSignature parses Transit's "vault:v<N>:<std base64>", requires N
// to be the pinned version and 64 bytes of signature, and verifies it
// over the job's input with the pair's public key, which catches a wrong
// key, a rotated mapping or a tampering proxy.
func checkSignature(key groupKey, j *signJob, s string) ([]byte, error) {
	sig, version, err := parseSignature(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrBadSignature, key.name, err)
	}
	if version != key.version {
		return nil, fmt.Errorf("%w: %s: signed with version %d, pinned %d", ErrBadSignature, key.name, version, key.version)
	}
	if !ed25519.Verify(j.pub, j.input, sig) {
		return nil, fmt.Errorf("%w: %s: signature does not verify under the key's public key", ErrBadSignature, key.name)
	}
	return sig, nil
}

// parseSignature splits "vault:v<N>:<std base64 of 64 bytes>". The
// version comes from the prefix because whether a batch result carries
// key_version is unverified.
func parseSignature(s string) ([]byte, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 || parts[0] != "vault" || !strings.HasPrefix(parts[1], "v") {
		return nil, 0, fmt.Errorf("unexpected signature format %q", s)
	}
	version, err := strconv.Atoi(parts[1][1:])
	if err != nil || version < 1 {
		return nil, 0, fmt.Errorf("unexpected signature version in %q", s)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return nil, 0, fmt.Errorf("signature is not standard base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, 0, fmt.Errorf("signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	return sig, version, nil
}
