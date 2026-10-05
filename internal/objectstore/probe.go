package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
)

// Access probes: ask the object store itself what a credential may do,
// rather than trusting the policy someone says is attached to it. The SaaS
// API uses them at startup to refuse a recipe credential that reaches
// beyond tenants/*/recipes/* (internal/saasapi, FIX.3). FLAG FOR SECURITY
// REVIEW.
//
// A probe is one real request. The answer is classified as:
//
//   - denied: the server answered AccessDenied (403);
//   - allowed: it did what was asked, or refused only for a reason it
//     checks after authorization (a missing key on a read, a failed
//     precondition on a write);
//   - inconclusive: anything else (a rejected credential, a missing bucket,
//     an unreachable endpoint after the retries).
//
// A put probe that succeeds created an object; ExpectDenied deletes it
// again (best effort, reported if that fails). Put probes are create-only
// (If-None-Match: *), so a probe never replaces an existing object, and
// ExpectDenied never deletes an object a probe didn't write. A delete
// probe targets a fresh key nothing wrote, so even an allowed one removes
// nothing (in a versioned bucket it leaves a delete marker at that key).

// ProbeOp is the request an access probe makes.
type ProbeOp string

const (
	// ProbePut creates an object at the key (create-only).
	ProbePut ProbeOp = "put"
	// ProbeGet reads the object at the key. Use a key that doesn't exist:
	// "no such key" counts as allowed, since the store only says so to a
	// caller it lets read there.
	ProbeGet ProbeOp = "get"
	// ProbeList lists one object under the key, used as a prefix.
	ProbeList ProbeOp = "list"
	// ProbeDelete deletes the object at the key. Use a fresh key that
	// doesn't exist: S3 answers a permitted delete of a missing key with
	// success (204) and a forbidden one with AccessDenied, whether or not
	// the caller may list the bucket, so the answer needs no object there.
	ProbeDelete ProbeOp = "delete"
)

// validProbeOp reports whether op is one TryAccess knows.
func validProbeOp(op ProbeOp) bool {
	switch op {
	case ProbePut, ProbeGet, ProbeList, ProbeDelete:
		return true
	}
	return false
}

// Probe is one access probe: an operation on a key (or, for ProbeList, a
// prefix) of the store's bucket.
type Probe struct {
	Op  ProbeOp
	Key string
}

func (p Probe) String() string {
	if p.Key == "" {
		return fmt.Sprintf("%s (bucket root)", p.Op)
	}
	return fmt.Sprintf("%s %s", p.Op, p.Key)
}

// Access is a probe's classified outcome.
type Access int

const (
	// AccessUnknown: the probe couldn't tell (see TryAccess's error).
	AccessUnknown Access = iota
	// AccessDenied: the store answered AccessDenied.
	AccessDenied
	// AccessAllowed: the store let the request through.
	AccessAllowed
)

func (a Access) String() string {
	switch a {
	case AccessDenied:
		return "denied"
	case AccessAllowed:
		return "allowed"
	}
	return "unknown"
}

// probeBody is what a put probe writes.
var probeBody = []byte("imas access probe: this object should not exist; delete it\n")

// TryAccess makes probe p once and classifies the answer. It returns a
// non-nil error only with AccessUnknown. A put probe that is allowed may
// have created an object at p.Key; the caller removes it (ExpectDenied
// does).
func (s *Store) TryAccess(ctx context.Context, p Probe) (Access, error) {
	a, _, err := s.tryAccess(ctx, p)
	return a, err
}

// tryAccess is TryAccess that also reports whether a put probe created
// its object.
func (s *Store) tryAccess(ctx context.Context, p Probe) (Access, bool, error) {
	var err error
	switch p.Op {
	case ProbePut:
		_, err = s.PutConditional(ctx, p.Key, probeBody, "text/plain", PutCondition{IfNoneMatch: true})
		if err == nil {
			return AccessAllowed, true, nil
		}
		if errors.Is(err, ErrPreconditionFailed) {
			// Something is already there, and the store evaluated the
			// condition: it authorized the write first.
			return AccessAllowed, false, nil
		}
	case ProbeGet:
		err = s.probeGet(ctx, p.Key)
		if err != nil && errorCode(err) == "NoSuchKey" {
			return AccessAllowed, false, nil
		}
	case ProbeList:
		_, _, err = s.ListPage(ctx, p.Key, "", 1)
	case ProbeDelete:
		err = s.client.RemoveObject(ctx, s.bucket, p.Key, minio.RemoveObjectOptions{})
		if err != nil && errorCode(err) == "NoSuchKey" {
			// Some stores say so for a missing key, after authorizing.
			return AccessAllowed, false, nil
		}
	default:
		return AccessUnknown, false, fmt.Errorf("objectstore: unknown probe operation %q", p.Op)
	}
	if err == nil {
		return AccessAllowed, false, nil
	}
	if errorCode(err) == "AccessDenied" {
		return AccessDenied, false, nil
	}
	return AccessUnknown, false, err
}

// probeGet reads at most one byte of key, so the store answers the GET
// (minio-go sends it on the first read or stat) without the probe holding
// a large object.
func (s *Store) probeGet(ctx context.Context, key string) error {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return err
	}
	defer obj.Close()
	if _, err := obj.Read(make([]byte, 1)); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// errorCode is the S3 error code inside err ("" when err holds none, such
// as a network error). minio.ToErrorResponse doesn't unwrap, hence
// errors.As.
func errorCode(err error) string {
	var resp minio.ErrorResponse
	if errors.As(err, &resp) {
		return resp.Code
	}
	return ""
}

// retryable reports whether a probe that couldn't tell may tell on a later
// attempt: the store wasn't reached, or answered that it is busy or broken.
// Any other answer (a rejected credential, a missing bucket) won't change.
func retryable(err error) bool {
	var resp minio.ErrorResponse
	if !errors.As(err, &resp) {
		return true
	}
	if resp.StatusCode >= 500 {
		return true
	}
	switch resp.Code {
	case "SlowDown", "ServiceUnavailable", "InternalError", "RequestTimeout", "RequestTimeTooSkewed":
		return true
	}
	return false
}

// ErrAccessAllowed is wrapped by the *AllowedError ExpectDenied returns
// when the store allowed a probe it should have denied.
var ErrAccessAllowed = errors.New("objectstore: the store allowed access that should be denied")

// ErrProbeInconclusive is wrapped by ExpectDenied's error when a probe got
// no answer it could classify, so nothing is known about that access.
var ErrProbeInconclusive = errors.New("objectstore: access probe inconclusive")

// AllowedError lists the probes the store allowed.
type AllowedError struct {
	Allowed []Probe
	// Leftovers are put probes' objects that could not be deleted again,
	// with why; empty when every one was removed.
	Leftovers []string
}

func (e *AllowedError) Error() string {
	names := make([]string, len(e.Allowed))
	for i, p := range e.Allowed {
		names[i] = p.String()
	}
	msg := fmt.Sprintf("%v: %s", ErrAccessAllowed, strings.Join(names, ", "))
	if len(e.Leftovers) > 0 {
		msg += fmt.Sprintf(" (probe objects left behind, delete them by hand: %s)", strings.Join(e.Leftovers, "; "))
	}
	return msg
}

func (e *AllowedError) Unwrap() error { return ErrAccessAllowed }

// ExpectDenied makes every probe, retrying one that couldn't tell (an
// unreachable store, a 5xx) with rp's backoff, and returns nil only if the
// store denied all of them. Otherwise it returns an *AllowedError naming
// every probe the store allowed (after making them all, and deleting what
// the allowed put probes created), or, when none was allowed but one
// stayed unclassified, an error wrapping ErrProbeInconclusive. Fail
// closed: "couldn't tell" is never "denied".
func (s *Store) ExpectDenied(ctx context.Context, probes []Probe, rp RetryPolicy) error {
	rp = rp.withDefaults()
	for _, p := range probes {
		if !validProbeOp(p.Op) {
			return fmt.Errorf("objectstore: unknown probe operation %q", p.Op)
		}
	}
	var allowed []Probe
	created := map[string]bool{}
	var inconclusive []error
	for _, p := range probes {
		a, c, err := s.tryWithRetry(ctx, p, rp)
		switch a {
		case AccessAllowed:
			allowed = append(allowed, p)
			created[p.Key] = created[p.Key] || c
		case AccessUnknown:
			inconclusive = append(inconclusive, fmt.Errorf("%s: %w", p, err))
		}
	}
	if len(allowed) > 0 {
		e := &AllowedError{Allowed: allowed}
		for _, p := range allowed {
			if p.Op != ProbePut {
				continue
			}
			// A fresh context: the caller's may be what ran out.
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rp.AttemptTimeout)
			if err := s.removeProbeObject(dctx, p.Key, created[p.Key]); err != nil {
				e.Leftovers = append(e.Leftovers, fmt.Sprintf("%s (%v)", p.Key, err))
			}
			cancel()
		}
		return e
	}
	if len(inconclusive) > 0 {
		return fmt.Errorf("%w: %w", ErrProbeInconclusive, errors.Join(inconclusive...))
	}
	return nil
}

// removeProbeObject deletes what an allowed put probe left at key: the
// object it created, or, when the store refused the create because the
// key was taken, the object there only if it holds exactly probeBody (an
// earlier attempt whose answer was lost). Anything else at the key is
// not the probe's and is left alone.
func (s *Store) removeProbeObject(ctx context.Context, key string, created bool) error {
	if !created {
		data, err := s.GetLimited(ctx, key, int64(len(probeBody)))
		switch {
		case IsNotExist(err), errors.Is(err, ErrObjectTooLarge):
			return nil
		case err != nil:
			return fmt.Errorf("could not check whether it is the probe's: %w", err)
		case string(data) != string(probeBody):
			return nil
		}
	}
	return s.Delete(ctx, key)
}

func (s *Store) tryWithRetry(ctx context.Context, p Probe, rp RetryPolicy) (Access, bool, error) {
	for attempt := 1; ; attempt++ {
		actx, cancel := context.WithTimeout(ctx, rp.AttemptTimeout)
		a, created, err := s.tryAccess(actx, p)
		cancel()
		if a != AccessUnknown || !retryable(err) {
			return a, created, err
		}
		if ctx.Err() != nil {
			return AccessUnknown, false, errors.Join(ctx.Err(), err)
		}
		if attempt >= rp.MaxAttempts {
			return AccessUnknown, false, fmt.Errorf("no answer after %d attempts: %w", attempt, err)
		}
		wait := jitter(rp.backoff(attempt))
		if rp.OnRetry != nil {
			rp.OnRetry(attempt, wait, err)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return AccessUnknown, false, errors.Join(ctx.Err(), err)
		case <-t.C:
		}
	}
}
