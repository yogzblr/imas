package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	httpc "net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/yogzblr/imas/internal/ingredients/file"
	"github.com/yogzblr/imas/internal/ingredients/file/hashers"
)

type HTTPFile struct {
	ID          string
	Source      string
	Destination string
	Hash        string
	Props       map[string]interface{}
}

const downloadTempPattern = ".imas-http-download-*"

// PropRootCAFile names a PEM file whose certificates become the ONLY
// trust roots for this download, in place of the system CA pool — the
// same pinning the sprout's own farmer/NATS connection does to
// config.SproutRootCA (cmd/sprout's ConnectSprout). When it's set the
// source must be https://, and a redirect may only go to another https://
// URL (it is verified against the same pinned roots). The selfupdate
// ingredient always sets it to config.SproutRootCA. Unset, downloads use
// http.DefaultClient and the system pool, as before.
const PropRootCAFile = "rootCAFile"

var (
	// ErrPinnedRootsRequireHTTPS: PropRootCAFile was set for a plain
	// http:// source, where there is no TLS to pin.
	ErrPinnedRootsRequireHTTPS = errors.New("http file provider: a pinned root CA requires an https:// source")
	// ErrPinnedRootsUnusable: PropRootCAFile couldn't be read or holds no
	// certificates. The download fails rather than falling back to the
	// system pool.
	ErrPinnedRootsUnusable = errors.New("http file provider: pinned root CA file is unusable")
)

// Compile-time interface check.
var _ file.FileProvider = HTTPFile{}

func (hf HTTPFile) Download(ctx context.Context) error {
	method := httpc.MethodGet
	if hf.Props["method"] != nil {
		if m, okM := hf.Props["method"].(string); okM {
			method = m
		}
	}
	req, err := httpc.NewRequestWithContext(ctx, method, hf.Source, nil)
	if err != nil {
		return err
	}
	if err := applyRequestHeaders(req, hf.Props["headers"]); err != nil {
		return err
	}
	client, err := hf.client()
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	expectedCode := httpc.StatusOK
	if hf.Props["expectedCode"] != nil {
		if ec, okEC := hf.Props["expectedCode"].(int); okEC {
			expectedCode = ec
		}
	}
	if res.StatusCode != expectedCode {
		// TODO standardize this error message
		return fmt.Errorf("unexpected HTTP status code %d", res.StatusCode)
	}
	destinationDir := filepath.Dir(hf.Destination)
	stagedFile, err := os.CreateTemp(destinationDir, downloadTempPattern)
	if err != nil {
		return err
	}
	stagedPath := stagedFile.Name()
	cleanupStaged := true
	defer func() {
		if cleanupStaged {
			os.Remove(stagedPath)
		}
	}()

	_, copyErr := io.Copy(stagedFile, res.Body)
	closeErr := stagedFile.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	// os.CreateTemp creates the staged file with mode 0600. Preserve the
	// existing destination's mode when replacing it, otherwise fall back to
	// 0644 (honoring umask) to match the prior os.Create behavior instead of
	// silently tightening permissions to 0600.
	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(hf.Destination); statErr == nil {
		mode = info.Mode().Perm()
	}
	if err := os.Chmod(stagedPath, mode); err != nil {
		return err
	}
	if err := os.Rename(stagedPath, hf.Destination); err != nil {
		return err
	}
	cleanupStaged = false
	return nil
}

// client returns http.DefaultClient, or, when PropRootCAFile is set, a
// client that trusts only that file's certificates.
func (hf HTTPFile) client() (*httpc.Client, error) {
	raw, set := hf.Props[PropRootCAFile]
	if !set || raw == nil {
		return httpc.DefaultClient, nil
	}
	caFile, ok := raw.(string)
	if !ok || caFile == "" {
		return nil, fmt.Errorf("%w: %s must be a non-empty path", ErrPinnedRootsUnusable, PropRootCAFile)
	}
	u, err := url.Parse(hf.Source)
	if err != nil || u.Scheme != "https" {
		return nil, ErrPinnedRootsRequireHTTPS
	}
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPinnedRootsUnusable, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%w: no certificates in %s", ErrPinnedRootsUnusable, caFile)
	}
	transport := httpc.DefaultTransport.(*httpc.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &httpc.Client{
		Transport: transport,
		CheckRedirect: func(req *httpc.Request, via []*httpc.Request) error {
			if req.URL.Scheme != "https" {
				return ErrPinnedRootsRequireHTTPS
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}, nil
}

func applyRequestHeaders(req *httpc.Request, headers interface{}) error {
	if headers == nil {
		return nil
	}

	switch typedHeaders := headers.(type) {
	case map[string]string:
		for headerName, headerValue := range typedHeaders {
			req.Header.Set(headerName, headerValue)
		}
	case map[string]interface{}:
		for headerName, rawHeaderValue := range typedHeaders {
			headerValues, err := normalizeHeaderValues(headerName, rawHeaderValue)
			if err != nil {
				return err
			}
			setHeaderValues(req.Header, headerName, headerValues)
		}
	case httpc.Header:
		req.Header = typedHeaders.Clone()
	default:
		return fmt.Errorf("headers property must be a map, got %T", headers)
	}

	return nil
}

func normalizeHeaderValues(headerName string, rawHeaderValue interface{}) ([]string, error) {
	switch headerValue := rawHeaderValue.(type) {
	case string:
		return []string{headerValue}, nil
	case []string:
		return headerValue, nil
	case []interface{}:
		values := make([]string, 0, len(headerValue))
		for _, rawValue := range headerValue {
			value, ok := rawValue.(string)
			if !ok {
				return nil, fmt.Errorf("header %q value must contain only strings", headerName)
			}
			values = append(values, value)
		}
		return values, nil
	default:
		return nil, fmt.Errorf("header %q value must be a string or string array", headerName)
	}
}

func setHeaderValues(headers httpc.Header, headerName string, headerValues []string) {
	headers.Del(headerName)
	for _, headerValue := range headerValues {
		headers.Add(headerName, headerValue)
	}
}

func (hf HTTPFile) Properties() (map[string]interface{}, error) {
	return hf.Props, nil
}

func (hf HTTPFile) Parse(id, source, destination, hash string, properties map[string]interface{}) (file.FileProvider, error) {
	if properties == nil {
		properties = make(map[string]interface{})
	}
	return HTTPFile{ID: id, Source: source, Destination: destination, Hash: hash, Props: properties}, nil
}

func (hf HTTPFile) Protocols() []string {
	return []string{"http", "https"}
}

func (lf HTTPFile) Verify(ctx context.Context) (bool, error) {
	hashType := ""
	if lf.Props["hashType"] == nil {
		hashType = hashers.GuessHashType(lf.Hash)
	} else if ht, ok := lf.Props["hashType"].(string); !ok {
		hashType = hashers.GuessHashType(lf.Hash)
	} else {
		hashType = ht
	}
	cf := hashers.CacheFile{
		ID:          lf.ID,
		Destination: lf.Destination,
		Hash:        lf.Hash,
		HashType:    hashType,
	}
	return cf.Verify(ctx)
}

func init() {
	file.RegisterProvider(HTTPFile{})
}
