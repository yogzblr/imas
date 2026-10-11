package natsbootstrap

// A minimal in-cluster Kubernetes REST client for the one object this
// subcommand touches: the trust ConfigMap in the pod's own namespace
// (brief §4.2 step 4). It authenticates with the pod's projected service
// account token, re-read on every request because the kubelet rotates
// it, and verifies the API server with the service account's ca.crt.
// The Job's Role (PR6) grants configmaps create, and get/update/patch on
// the trust ConfigMap's name only.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// serviceAccountDir is where Kubernetes mounts a pod's service account
// token, CA bundle and namespace. A variable so tests can point it at a
// temporary directory.
var serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

// kubeRequestTimeout bounds each request to the API server.
const kubeRequestTimeout = 30 * time.Second

// errConflict is a 409 from the API server: the ConfigMap was created or
// changed since it was read.
var errConflict = errors.New("natsbootstrap: configmap changed concurrently (409 conflict)")

// configMapNameMatcher is a DNS-1123 subdomain, the rule for a ConfigMap
// name; it also keeps the name to one URL path segment.
var configMapNameMatcher = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)

// configMap is a core/v1 ConfigMap. Metadata is kept as decoded so an
// update sends back every field it was read with (labels, annotations,
// resourceVersion, ...), not only the ones this package knows.
type configMap struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   map[string]any    `json:"metadata"`
	Data       map[string]string `json:"data,omitempty"`
	BinaryData map[string]string `json:"binaryData,omitempty"`
	Immutable  *bool             `json:"immutable,omitempty"`
}

type kubeClient struct {
	base      string // https://host:port
	namespace string
	tokenPath string
	http      *http.Client
}

// inClusterKube builds a client from the pod's environment: the API
// server from KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT, the
// namespace, token and CA from serviceAccountDir.
func inClusterKube() (*kubeClient, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("natsbootstrap: not running in a Kubernetes pod (KUBERNETES_SERVICE_HOST/PORT unset)")
	}
	ns, err := os.ReadFile(filepath.Join(serviceAccountDir, "namespace"))
	if err != nil {
		return nil, fmt.Errorf("natsbootstrap: reading the pod namespace: %w", err)
	}
	namespace := strings.TrimSpace(string(ns))
	if !configMapNameMatcher.MatchString(namespace) {
		return nil, fmt.Errorf("natsbootstrap: pod namespace %q is not a valid name", namespace)
	}
	caPEM, err := os.ReadFile(filepath.Join(serviceAccountDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("natsbootstrap: reading the API server CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("natsbootstrap: no certificates in the service account ca.crt")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // the API server is reached directly, never via a proxy
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &kubeClient{
		base:      "https://" + net.JoinHostPort(host, port),
		namespace: namespace,
		tokenPath: filepath.Join(serviceAccountDir, "token"),
		http:      &http.Client{Transport: tr, Timeout: kubeRequestTimeout},
	}, nil
}

func (k *kubeClient) close() { k.http.CloseIdleConnections() }

func (k *kubeClient) configMapsURL() string {
	return k.base + "/api/v1/namespaces/" + url.PathEscape(k.namespace) + "/configmaps"
}

// getConfigMap returns the ConfigMap, or nil when it does not exist.
func (k *kubeClient) getConfigMap(ctx context.Context, name string) (*configMap, error) {
	var cm configMap
	code, err := k.do(ctx, http.MethodGet, k.configMapsURL()+"/"+url.PathEscape(name), nil, &cm)
	if code == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("natsbootstrap: reading configmap %s/%s: %w", k.namespace, name, err)
	}
	return &cm, nil
}

// createConfigMap creates cm; an existing one is errConflict.
func (k *kubeClient) createConfigMap(ctx context.Context, cm *configMap) error {
	_, err := k.do(ctx, http.MethodPost, k.configMapsURL(), cm, nil)
	if err != nil {
		return fmt.Errorf("natsbootstrap: creating configmap %s/%s: %w", k.namespace, metaName(cm), err)
	}
	return nil
}

// updateConfigMap replaces cm, which carries the resourceVersion it was
// read at; a change since is errConflict.
func (k *kubeClient) updateConfigMap(ctx context.Context, cm *configMap) error {
	_, err := k.do(ctx, http.MethodPut, k.configMapsURL()+"/"+url.PathEscape(metaName(cm)), cm, nil)
	if err != nil {
		return fmt.Errorf("natsbootstrap: updating configmap %s/%s: %w", k.namespace, metaName(cm), err)
	}
	return nil
}

func metaName(cm *configMap) string {
	s, _ := cm.Metadata["name"].(string)
	return s
}

// do sends one request and decodes a 2xx answer into out (if not nil).
// It returns the status code (0 if none was received); 409 is
// errConflict, any other non-2xx an error carrying the API's message.
func (k *kubeClient) do(ctx context.Context, method, u string, body, out any) (int, error) {
	token, err := os.ReadFile(k.tokenPath)
	if err != nil {
		return 0, fmt.Errorf("reading the service account token: %w", err)
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	switch {
	case resp.StatusCode == http.StatusConflict:
		return resp.StatusCode, errConflict
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		var st struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &st)
		if st.Message == "" {
			st.Message = http.StatusText(resp.StatusCode)
		}
		return resp.StatusCode, fmt.Errorf("status %d: %s", resp.StatusCode, st.Message)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decoding the API server's answer: %w", err)
		}
	}
	return resp.StatusCode, nil
}
