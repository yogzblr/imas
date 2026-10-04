// Package objectstoretest provides a minimal in-process fake of the
// S3/MinIO wire protocol, just enough to exercise internal/objectstore's
// Store methods (and anything built on top of it, like internal/cook's
// recipe resolution) without a real S3/MinIO server. It's a separate,
// exported package — rather than an unexported helper duplicated in every
// consumer's _test.go files — because internal/objectstore's own tests
// and internal/cook's both need it.
//
// It doesn't validate request signing, and understands just enough of
// the protocol (GET/PUT/HEAD/DELETE on objects, HEAD on the bucket,
// ListObjectsV2 with start-after, GetBucketLocation, aws-chunked
// streaming-signature bodies, and PUT's If-Match / If-None-Match
// conditions against an MD5 ETag) for minio-go's client to consider it a
// working single-node endpoint.
package objectstoretest

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/objectstore"
)

const bucket = "test-bucket"

type fakeS3 struct {
	mu   sync.Mutex
	data map[string]*object // key -> object, within the fixed test bucket

	// failures queues injected error responses (see Server.FailNext),
	// consumed one per request.
	failures []failure

	// beforePut, if set, runs (with mu held) before each PUT is applied;
	// see Server.BeforePut.
	beforePut func(key string)
}

// object is one stored object: its content, ETag (the hex MD5 of the
// content, as S3 gives a single-part upload) and modification time.
type object struct {
	data    []byte
	etag    string
	modTime time.Time
}

func newObject(data []byte) *object {
	sum := md5.Sum(data)
	return &object{data: data, etag: hex.EncodeToString(sum[:]), modTime: time.Now().UTC()}
}

func (o *object) setHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Length", strconv.Itoa(len(o.data)))
	w.Header().Set("ETag", `"`+o.etag+`"`)
	w.Header().Set("Last-Modified", o.modTime.Format(http.TimeFormat))
}

type failure struct {
	status int
	code   string
}

// Server is a handle on a fake S3 server, for tests that open their own
// clients against it (e.g. to exercise Store.WaitReady) or inject failures.
type Server struct {
	f   *fakeS3
	srv *httptest.Server
}

// NewServer starts an in-process fake S3 server, closed automatically via
// t.Cleanup.
func NewServer(t *testing.T) *Server {
	t.Helper()
	s := startServer()
	t.Cleanup(s.srv.Close)
	return s
}

// Config returns an objectstore.Config pointing at this server's bucket.
func (s *Server) Config() objectstore.Config {
	return objectstore.Config{
		Endpoint:        strings.TrimPrefix(s.srv.URL, "http://"),
		AccessKeyID:     "test",
		SecretAccessKey: "test",
		Bucket:          bucket,
	}
}

// FailNext makes the next n requests fail with the given HTTP status and
// S3 error code (e.g. 404/"NoSuchBucket", 403/"AccessDenied"). Bucket
// location lookups aren't counted: minio-go makes them only on some calls
// and treats some of their errors as non-fatal, so counting them would
// make tests depend on minio-go internals.
func (s *Server) FailNext(n int, status int, code string) {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	for range n {
		s.f.failures = append(s.f.failures, failure{status: status, code: code})
	}
}

// BeforePut installs fn to run before every PUT is applied, with the
// server's lock held, so a test can change the stored objects between a
// client's read and its conditional write (a concurrent writer). fn may
// call Server.Set but nothing that takes the lock. Nil removes it.
func (s *Server) BeforePut(fn func(key string)) {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	s.f.beforePut = fn
}

// Set stores content at key directly, as another writer would. It must
// only be called from a BeforePut hook (the lock is already held).
func (s *Server) Set(key, content string) {
	s.f.data[key] = newObject([]byte(content))
}

// Keys returns every stored key, sorted.
func (s *Server) Keys() []string {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	keys := make([]string, 0, len(s.f.data))
	for k := range s.f.data {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// Object returns the content stored at key and whether there is one.
func (s *Server) Object(key string) (string, bool) {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	obj, ok := s.f.data[key]
	if !ok {
		return "", false
	}
	return string(obj.data), true
}

// NewStore starts an in-process fake S3 server and returns an
// objectstore.Store connected to it, scoped to its own bucket. The server
// is closed automatically via t.Cleanup.
func NewStore(t *testing.T) *objectstore.Store {
	t.Helper()
	store, closeFn, err := newStore()
	if err != nil {
		t.Fatalf("objectstoretest: opening fake store: %v", err)
	}
	t.Cleanup(closeFn)
	return store
}

// NewStoreForBinary is NewStore for a TestMain(m *testing.M) setup, which
// has no *testing.T to hang t.Cleanup off of — the caller is responsible
// for calling the returned close func once the test binary is done (e.g.
// deferred around m.Run()).
func NewStoreForBinary() (store *objectstore.Store, closeFn func(), err error) {
	return newStore()
}

// NewSharedStores starts one in-process fake S3 server and returns n
// independently opened objectstore.Store clients all pointed at its single
// bucket — the test stand-in for n farmer replicas sharing one real
// S3/MinIO bucket. A write through any one of them is visible to every
// other. The server is closed automatically via t.Cleanup.
func NewSharedStores(t *testing.T, n int) []*objectstore.Store {
	t.Helper()
	srv := NewServer(t)
	stores := make([]*objectstore.Store, n)
	for i := range stores {
		s, err := objectstore.Open(srv.Config())
		if err != nil {
			t.Fatalf("objectstoretest: opening shared fake store %d: %v", i, err)
		}
		stores[i] = s
	}
	return stores
}

func newStore() (*objectstore.Store, func(), error) {
	srv := startServer()
	store, err := objectstore.Open(srv.Config())
	if err != nil {
		srv.srv.Close()
		return nil, nil, err
	}
	return store, srv.srv.Close, nil
}

func startServer() *Server {
	f := &fakeS3{data: make(map[string]*object)}
	return &Server{f: f, srv: httptest.NewServer(http.HandlerFunc(f.handle))}
}

// Seed uploads files (key -> content) directly into the fake server's
// backing store, for tests that need existing objects in place before
// exercising a read path.
func Seed(t *testing.T, store *objectstore.Store, files map[string]string) {
	t.Helper()
	for key, content := range files {
		if err := store.Put(context.Background(), key, []byte(content)); err != nil {
			t.Fatalf("objectstoretest: seeding %s: %v", key, err)
		}
	}
}

func (f *fakeS3) handle(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	// parts[0] is the bucket name. Object requests aren't checked against
	// it (every test targets the same fixed bucket); a bucket-level HEAD
	// (objectstore.Ping) is, so tests can exercise a missing bucket.
	var key string
	if len(parts) > 1 {
		key = parts[1]
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if _, isLocation := r.URL.Query()["location"]; !isLocation && len(f.failures) > 0 {
		fail := f.failures[0]
		f.failures = f.failures[1:]
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(fail.status)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` +
			`<Error><Code>` + fail.code + `</Code><Message>injected failure</Message></Error>`))
		return
	}

	if r.Method == http.MethodHead && key == "" {
		if parts[0] == bucket {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
		return
	}

	switch r.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Content-Encoding") == "aws-chunked" || strings.Contains(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING") {
			body = decodeAWSChunked(body)
		}
		if f.beforePut != nil {
			f.beforePut(key)
		}
		if !f.putConditionHolds(key, r.Header) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusPreconditionFailed)
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` +
				`<Error><Code>PreconditionFailed</Code><Message>At least one of the pre-conditions you specified did not hold</Message></Error>`))
			return
		}
		obj := newObject(body)
		f.data[key] = obj
		w.Header().Set("ETag", `"`+obj.etag+`"`)
		w.WriteHeader(http.StatusOK)
	case http.MethodHead:
		if obj, ok := f.data[key]; ok {
			obj.setHeaders(w)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	case http.MethodGet:
		if _, ok := r.URL.Query()["location"]; ok {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`))
			return
		}
		if r.URL.Query().Get("list-type") == "2" {
			f.handleList(w, r.URL.Query().Get("prefix"), r.URL.Query().Get("start-after"))
			return
		}
		obj, ok := f.data[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>` +
				`<Error><Code>NoSuchKey</Code><Message>no such key</Message><Key>` + key + `</Key></Error>`))
			return
		}
		obj.setHeaders(w)
		w.WriteHeader(http.StatusOK)
		w.Write(obj.data)
	case http.MethodDelete:
		// S3 answers 204 whether or not the key existed.
		delete(f.data, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// putConditionHolds evaluates a PUT's If-Match / If-None-Match headers
// against the object at key, as S3 does: If-None-Match "*" needs no
// object, If-Match "*" any object, and If-Match "<etag>" that ETag.
func (f *fakeS3) putConditionHolds(key string, h http.Header) bool {
	obj, exists := f.data[key]
	if v := h.Get("If-None-Match"); v != "" {
		if v == "*" {
			return !exists
		}
		return !exists || strings.Trim(v, `"`) != obj.etag
	}
	if v := h.Get("If-Match"); v != "" {
		if !exists {
			return false
		}
		return v == "*" || strings.Trim(v, `"`) == obj.etag
	}
	return true
}

type listContents struct {
	Key          string `xml:"Key"`
	Size         int64  `xml:"Size"`
	ETag         string `xml:"ETag"`
	LastModified string `xml:"LastModified"`
}

type listResult struct {
	XMLName  xml.Name       `xml:"ListBucketResult"`
	Name     string         `xml:"Name"`
	Prefix   string         `xml:"Prefix"`
	Contents []listContents `xml:"Contents"`
}

// handleList answers ListObjectsV2 in one untruncated page, in key order
// (as S3 lists), starting after startAfter when it is set.
func (f *fakeS3) handleList(w http.ResponseWriter, prefix, startAfter string) {
	result := listResult{Name: bucket, Prefix: prefix}
	keys := make([]string, 0, len(f.data))
	for k := range f.data {
		if prefix != "" && !strings.HasPrefix(k, prefix) {
			continue
		}
		if startAfter != "" && k <= startAfter {
			continue
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		obj := f.data[k]
		result.Contents = append(result.Contents, listContents{
			Key: k, Size: int64(len(obj.data)), ETag: `"` + obj.etag + `"`,
			LastModified: obj.modTime.Format(time.RFC3339Nano),
		})
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	out, _ := xml.Marshal(result)
	w.Write(out)
}

// decodeAWSChunked strips the aws-chunked streaming-signature framing
// (`<hex-size>[;chunk-signature=...]\r\n<data>\r\n`, repeated, terminated
// by a zero-size chunk) minio-go's signature v4 streaming upload wraps
// the body in, so the fake server stores the same bytes Put() was called
// with.
func decodeAWSChunked(body []byte) []byte {
	var out []byte
	for len(body) > 0 {
		nl := indexCRLF(body)
		if nl < 0 {
			break
		}
		header := string(body[:nl])
		if semi := strings.IndexByte(header, ';'); semi >= 0 {
			header = header[:semi]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(header), 16, 64)
		if err != nil {
			break
		}
		body = body[nl+2:]
		if size == 0 {
			break
		}
		out = append(out, body[:size]...)
		body = body[size+2:] // skip the chunk's trailing \r\n
	}
	return out
}

func indexCRLF(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}
