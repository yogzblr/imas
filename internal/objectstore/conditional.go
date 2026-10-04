package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/minio/minio-go/v7"
)

// Conditional writes and listings with object info, for writers that must
// not overwrite each other silently (the SaaS API's recipe upload, REC.1).
//
// Conditional PUT uses the S3 If-Match / If-None-Match request headers,
// which AWS S3 (since 2024) and MinIO both honour: the server compares the
// condition with the object's current ETag and writes nothing on a
// mismatch, answering 412. That makes "read, check, write" a real
// compare-and-swap rather than a race window.

// ObjectInfo is what a stat, a read or a listing reports about one object.
type ObjectInfo struct {
	Key          string
	Size         int64
	LastModified time.Time
	// ETag is the server's entity tag, without quotes. For a single-part
	// upload without SSE-KMS it is the MD5 of the content; callers must
	// treat it as opaque and use it only as a write precondition.
	ETag string
}

// PutCondition is the precondition of a PutConditional. Exactly one of
// its fields must be set.
type PutCondition struct {
	// IfMatchETag writes only if the object exists with this ETag.
	IfMatchETag string
	// IfNoneMatch writes only if no object exists at the key.
	IfNoneMatch bool
}

// ErrPreconditionFailed is returned (wrapped) by PutConditional when the
// server refused the write because its condition did not hold: the object
// changed, appeared or disappeared since the caller read it.
var ErrPreconditionFailed = errors.New("objectstore: write precondition failed")

// ErrNoCondition is returned by PutConditional for a PutCondition with
// neither or both fields set.
var ErrNoCondition = errors.New("objectstore: a conditional put needs exactly one condition")

// isPreconditionFailure reports whether err is the server refusing a
// conditional request: 412 PreconditionFailed, or S3's 409
// ConditionalRequestConflict, which it answers when another conditional
// write to the same key is in flight.
func isPreconditionFailure(err error) bool {
	resp := minio.ToErrorResponse(err)
	return resp.Code == minio.PreconditionFailed || resp.Code == "ConditionalRequestConflict" ||
		resp.StatusCode == 412
}

// PutConditional writes data to key only if cond holds, with contentType
// as the object's Content-Type. It returns ErrPreconditionFailed (wrapped)
// when the server refused the write because of cond, and the new object's
// ETag on success.
func (s *Store) PutConditional(ctx context.Context, key string, data []byte, contentType string, cond PutCondition) (ObjectInfo, error) {
	if (cond.IfMatchETag == "") == !cond.IfNoneMatch {
		return ObjectInfo{}, ErrNoCondition
	}
	opts := minio.PutObjectOptions{ContentType: contentType}
	if cond.IfNoneMatch {
		opts.SetMatchETagExcept("*")
	} else {
		opts.SetMatchETag(cond.IfMatchETag)
	}
	info, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(data), int64(len(data)), opts)
	if err != nil {
		if isPreconditionFailure(err) {
			return ObjectInfo{}, fmt.Errorf("%w: %s", ErrPreconditionFailed, key)
		}
		return ObjectInfo{}, fmt.Errorf("objectstore: putting %s: %w", key, err)
	}
	mod := info.LastModified
	if mod.IsZero() {
		mod = time.Now().UTC()
	}
	return ObjectInfo{Key: key, Size: int64(len(data)), LastModified: mod, ETag: info.ETag}, nil
}

// GetLimitedWithInfo is GetLimited that also returns the object's info
// (size, modification time, ETag) from the same response, so the ETag
// belongs to exactly the bytes returned. A missing key is reported the way
// IsNotExist recognises.
func (s *Store) GetLimitedWithInfo(ctx context.Context, key string, limit int64) ([]byte, ObjectInfo, error) {
	if limit < 0 {
		return nil, ObjectInfo{}, fmt.Errorf("objectstore: negative limit for %s", key)
	}
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, ObjectInfo{}, fmt.Errorf("objectstore: getting %s: %w", key, err)
	}
	defer obj.Close()
	st, err := obj.Stat()
	if err != nil {
		if IsNotExist(err) {
			return nil, ObjectInfo{}, err
		}
		return nil, ObjectInfo{}, fmt.Errorf("objectstore: stating %s: %w", key, err)
	}
	info := ObjectInfo{Key: key, Size: st.Size, LastModified: st.LastModified, ETag: st.ETag}
	if st.Size > limit {
		return nil, info, fmt.Errorf("%w: %s is over %d bytes", ErrObjectTooLarge, key, limit)
	}
	data, err := io.ReadAll(io.LimitReader(obj, limit+1))
	if err != nil {
		if IsNotExist(err) {
			return nil, ObjectInfo{}, err
		}
		return nil, ObjectInfo{}, fmt.Errorf("objectstore: reading %s: %w", key, err)
	}
	if int64(len(data)) > limit {
		return nil, info, fmt.Errorf("%w: %s is over %d bytes", ErrObjectTooLarge, key, limit)
	}
	return data, info, nil
}

// MaxListPage is the most objects ListPage returns in one call.
const MaxListPage = 10000

// ListPage returns up to max objects under prefix whose keys sort after
// startAfter (a full key; empty starts at the beginning), in key order,
// and whether more objects follow. max must be 1 to MaxListPage.
func (s *Store) ListPage(ctx context.Context, prefix, startAfter string, max int) ([]ObjectInfo, bool, error) {
	if max < 1 || max > MaxListPage {
		return nil, false, fmt.Errorf("objectstore: list page size %d out of range 1..%d", max, MaxListPage)
	}
	// minio-go pages through the listing itself; stop it once one more
	// object than asked for has arrived.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	opts := minio.ListObjectsOptions{Prefix: prefix, Recursive: true, StartAfter: startAfter, MaxKeys: min(max+1, 1000)}
	var out []ObjectInfo
	for obj := range s.client.ListObjects(ctx, s.bucket, opts) {
		if obj.Err != nil {
			return nil, false, fmt.Errorf("objectstore: listing %s: %w", prefix, obj.Err)
		}
		if len(out) == max {
			return out, true, nil
		}
		out = append(out, ObjectInfo{Key: obj.Key, Size: obj.Size, LastModified: obj.LastModified, ETag: obj.ETag})
	}
	return out, false, nil
}
