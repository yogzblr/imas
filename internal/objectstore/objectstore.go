// Package objectstore wraps the S3/MinIO client farmer uses to serve
// recipes and (through the same client, at a different key prefix) any
// other read-mostly, blob-shaped content that no longer belongs on a
// single replica's local disk — see docs/design/imas-master-plan.md
// Phase 1: farmer's basepath local-disk recipe tree doesn't survive
// horizontal scaling, since any replica needs to be able to serve any
// recipe.
//
// Git remains the authored source of truth for recipes; syncing a merged
// commit's tree into the bucket this package reads from is a deploy-time
// concern (e.g. a CI job invoked on merge to the recipes repo), not
// something farmer itself does — this package only implements farmer's
// read path (and Put, for that sync job or any other writer to use), not
// the sync job itself.
package objectstore

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/s3utils"
)

// Store is a thin, bucket-scoped wrapper around a minio-go client.
type Store struct {
	client *minio.Client
	bucket string
}

// Config holds the connection settings for Open.
type Config struct {
	// Endpoint is the S3/MinIO endpoint, host:port, no scheme.
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	// UseSSL selects https vs http for the endpoint connection.
	UseSSL bool
	Bucket string
}

// Open builds a client for the configured S3/MinIO endpoint. It makes no
// network calls, so it does not verify the endpoint is reachable or the
// bucket exists — use WaitReady for that (with retries), or Ping.
func Open(cfg Config) (*Store, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("objectstore: empty endpoint")
	}
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("objectstore: empty bucket")
	}
	if err := s3utils.CheckValidBucketName(cfg.Bucket); err != nil {
		return nil, fmt.Errorf("objectstore: invalid bucket %q: %w", cfg.Bucket, err)
	}
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		Secure: cfg.UseSSL,
		// Path-style addressing (bucket in the URL path, not a subdomain):
		// self-hosted MinIO is rarely set up with the wildcard DNS
		// virtual-hosted-style addressing needs, so this is the safer
		// default for the S3/MinIO target this package is built for.
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		return nil, fmt.Errorf("objectstore: connecting to %s: %w", cfg.Endpoint, err)
	}
	return &Store{client: client, bucket: cfg.Bucket}, nil
}

// IsNotExist reports whether err indicates the requested key doesn't
// exist, mirroring os.IsNotExist for callers migrated from a local-disk
// store.
func IsNotExist(err error) bool {
	if err == nil {
		return false
	}
	resp := minio.ToErrorResponse(err)
	return resp.Code == "NoSuchKey" || resp.Code == "NoSuchBucket"
}

// Get returns the full content of key.
func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("objectstore: getting %s: %w", key, err)
	}
	defer obj.Close()
	data, err := io.ReadAll(obj)
	if err != nil {
		// A GetObject error only surfaces once the stream is read, so a
		// missing key comes back here, not from GetObject itself — pass
		// it through unwrapped so IsNotExist(err) still works for callers.
		if IsNotExist(err) {
			return nil, err
		}
		return nil, fmt.Errorf("objectstore: reading %s: %w", key, err)
	}
	return data, nil
}

// Exists reports whether key is present in the bucket.
func (s *Store) Exists(ctx context.Context, key string) (bool, error) {
	_, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err == nil {
		return true, nil
	}
	if IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("objectstore: stating %s: %w", key, err)
}

// Size returns the byte size of key.
func (s *Store) Size(ctx context.Context, key string) (int64, error) {
	info, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return 0, fmt.Errorf("objectstore: stating %s: %w", key, err)
	}
	return info.Size, nil
}

// Put writes data to key, replacing any existing object there.
func (s *Store) Put(ctx context.Context, key string, data []byte) error {
	_, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{})
	if err != nil {
		return fmt.Errorf("objectstore: putting %s: %w", key, err)
	}
	return nil
}

// Delete removes key from the bucket. Deleting a key that doesn't exist
// is not an error (S3 DeleteObject semantics), so callers racing each
// other to remove the same object — e.g. several farmer replicas' job-log
// reapers — all succeed.
func (s *Store) Delete(ctx context.Context, key string) error {
	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("objectstore: deleting %s: %w", key, err)
	}
	return nil
}

// List returns every object key under prefix, recursively — the
// object-storage equivalent of filepath.WalkDir over a recipe directory
// tree.
func (s *Store) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	for obj := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("objectstore: listing %s: %w", prefix, obj.Err)
		}
		keys = append(keys, obj.Key)
	}
	return keys, nil
}
