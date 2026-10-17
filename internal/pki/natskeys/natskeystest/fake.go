// Package natskeystest is an in-process fake of the OpenBao endpoints
// internal/pki/natskeys uses: Transit's keys/<name> read and create,
// keys/<name>/soft-delete, keys/<name>/config (deletion_allowed only) and
// the hard delete of keys/<name>, sign/<name> (plain and batch), and the
// kubernetes auth login. It counts requests, injects faults and rotates
// keys, for natskeys's own tests and for tests elsewhere that need a
// KeyStore without OpenBao (design D7: OpenBao itself is tested only by
// the real-server tests).
//
// The response shapes follow captured real OpenBao responses
// (internal/gatewayjwt/testdata/openbao-v2.7.0): an ed25519 public_key
// is standard base64 of the raw 32 bytes, a signature is
// "vault:v<N>:<standard base64>". A create of an existing key is a
// no-op answered 204 here; OpenBao 2.7.1 answers 200 with the key, also
// without changing it.
package natskeystest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Token is the static token the fake accepts.
const Token = "natskeystest-token"

// Op names a kind of request, for counters and fault injection.
type Op string

const (
	OpReadKey    Op = "read"
	OpCreateKey  Op = "create"
	OpSoftDelete Op = "soft-delete"
	OpConfigKey  Op = "config"      // POST keys/<name>/config
	OpHardDelete Op = "hard-delete" // DELETE keys/<name>
	OpSign       Op = "sign"        // every sign request, plain or batch
	OpBatch      Op = "batch"       // counted in addition to OpSign for batch requests
	OpLogin      Op = "login"
)

// DropConnection as a FailNext status closes the connection without an
// answer: a network error to the client.
const DropConnection = -1

// KeyOptions are the attributes a key reports on read. NewKey's are the
// hardened defaults; tests flip them to build bad keys.
type KeyOptions struct {
	Type                 string // default "ed25519"
	Exportable           bool
	AllowPlaintextBackup bool
	ImportedKey          bool
	Derived              bool
	SoftDeleted          bool
	// OmitFlags leaves the hardening flags out of the read response.
	OmitFlags bool
}

type key struct {
	opts            KeyOptions
	versions        []ed25519.PrivateKey // index i is version i+1
	deletionAllowed bool
}

type fault struct {
	status int
	left   int
}

// Fake is a running fake server. Safe for concurrent use.
type Fake struct {
	URL string
	srv *httptest.Server

	mu        sync.Mutex
	keys      map[string]*key
	counts    map[Op]int
	faults    map[Op]*fault
	k8sRole   string
	k8sTokens map[string]bool
	k8sSeq    int

	mutateSignature func(name string, version int, input []byte, sig string) string
	itemError       func(input []byte) string
	signGate        chan struct{}
}

// New starts a fake, closed when t ends.
func New(t testing.TB) *Fake {
	t.Helper()
	f := &Fake{
		keys:      map[string]*key{},
		counts:    map[Op]int{},
		faults:    map[Op]*fault{},
		k8sTokens: map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/", f.serve)
	f.srv = httptest.NewServer(mux)
	f.URL = f.srv.URL
	t.Cleanup(f.srv.Close)
	return f
}

// SetEnv points identity prefix (natskeys.EnvPrefixSign, ...) at the
// fake with token auth and transit mount "transit", using t.Setenv (so
// t must not be parallel). The variable suffixes are natskeys's
// Env* constants, spelled out here because natskeys's own tests import
// this package.
func (f *Fake) SetEnv(t testing.TB, prefix string) {
	t.Helper()
	t.Setenv(prefix+"OPENBAO_ADDR", f.URL)
	t.Setenv(prefix+"OPENBAO_AUTH_METHOD", "token")
	t.Setenv(prefix+"OPENBAO_TOKEN", Token)
	t.Setenv(prefix+"OPENBAO_TRANSIT_MOUNT", "transit")
}

// EnableKubernetes makes auth/kubernetes/login accept role (with any
// non-empty JWT) and issue tokens the fake then accepts.
func (f *Fake) EnableKubernetes(role string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.k8sRole = role
}

// RevokeLoginTokens invalidates every token issued by the kubernetes
// login, as a policy change or revocation would.
func (f *Fake) RevokeLoginTokens() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.k8sTokens = map[string]bool{}
}

// NewKey creates a hardened ed25519 key name with one version and
// returns its public key.
func (f *Fake) NewKey(name string) ed25519.PublicKey {
	return f.PutKey(name, KeyOptions{})
}

// PutKey creates (or replaces) name with opts and one fresh version.
func (f *Fake) PutKey(name string, opts KeyOptions) ed25519.PublicKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return f.PutPrivateKey(name, opts, priv)
}

// PutPrivateKey creates (or replaces) name with opts and priv as its
// only version.
func (f *Fake) PutPrivateKey(name string, opts KeyOptions, priv ed25519.PrivateKey) ed25519.PublicKey {
	if opts.Type == "" {
		opts.Type = "ed25519"
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[name] = &key{opts: opts, versions: []ed25519.PrivateKey{priv}}
	return priv.Public().(ed25519.PublicKey)
}

// Rotate adds a new version to name and returns its public key.
func (f *Fake) Rotate(name string) ed25519.PublicKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.keys[name]
	k.versions = append(k.versions, priv)
	return priv.Public().(ed25519.PublicKey)
}

// PrivateKey returns version (1-based) of name, or nil.
func (f *Fake) PrivateKey(name string, version int) ed25519.PrivateKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.keys[name]
	if k == nil || version < 1 || version > len(k.versions) {
		return nil
	}
	return k.versions[version-1]
}

// Has reports whether name exists.
func (f *Fake) Has(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keys[name] != nil
}

// SoftDeleted reports whether name exists and is soft-deleted.
func (f *Fake) SoftDeleted(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.keys[name]
	return k != nil && k.opts.SoftDeleted
}

// Delete removes name entirely (a hard delete).
func (f *Fake) Delete(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.keys, name)
}

// SetMutateSignature sets (nil clears) a hook that rewrites each
// signature string before it is sent, to return another key's
// signature or a wrong version.
func (f *Fake) SetMutateSignature(fn func(name string, version int, input []byte, sig string) string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mutateSignature = fn
}

// SetItemError sets (nil clears) a hook returning an error message for a
// batch item by its input; a non-empty message replaces its signature.
func (f *Fake) SetItemError(fn func(input []byte) string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.itemError = fn
}

// SetSignGate sets (nil clears) a channel each sign request receives
// from before it is answered: close it to let them through.
func (f *Fake) SetSignGate(gate chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signGate = gate
}

// Count returns how many op requests the fake has received.
func (f *Fake) Count(op Op) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[op]
}

// ResetCounts zeroes the counters.
func (f *Fake) ResetCounts() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counts = map[Op]int{}
}

// FailNext makes the next n op requests answer status (or
// DropConnection) without doing anything. OpBatch is not injectable;
// use OpSign.
func (f *Fake) FailNext(op Op, status, n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.faults[op] = &fault{status: status, left: n}
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	if path == "auth/kubernetes/login" && r.Method == http.MethodPost {
		f.login(w, r)
		return
	}
	rest, ok := strings.CutPrefix(path, "transit/")
	if !ok {
		writeErr(w, http.StatusNotFound, "no handler for route")
		return
	}
	var op Op
	var name string
	switch {
	case strings.HasPrefix(rest, "sign/") && (r.Method == http.MethodPost || r.Method == http.MethodPut):
		op, name = OpSign, strings.TrimPrefix(rest, "sign/")
	case strings.HasPrefix(rest, "keys/") && strings.HasSuffix(rest, "/soft-delete") && r.Method == http.MethodDelete:
		op, name = OpSoftDelete, strings.TrimSuffix(strings.TrimPrefix(rest, "keys/"), "/soft-delete")
	case strings.HasPrefix(rest, "keys/") && strings.HasSuffix(rest, "/config") && (r.Method == http.MethodPost || r.Method == http.MethodPut):
		op, name = OpConfigKey, strings.TrimSuffix(strings.TrimPrefix(rest, "keys/"), "/config")
	case strings.HasPrefix(rest, "keys/") && r.Method == http.MethodDelete:
		op, name = OpHardDelete, strings.TrimPrefix(rest, "keys/")
	case strings.HasPrefix(rest, "keys/") && r.Method == http.MethodGet:
		op, name = OpReadKey, strings.TrimPrefix(rest, "keys/")
	case strings.HasPrefix(rest, "keys/") && (r.Method == http.MethodPost || r.Method == http.MethodPut):
		op, name = OpCreateKey, strings.TrimPrefix(rest, "keys/")
	default:
		writeErr(w, http.StatusMethodNotAllowed, "unsupported operation")
		return
	}
	if strings.Contains(name, "/") {
		writeErr(w, http.StatusNotFound, "no handler for route")
		return
	}
	f.mu.Lock()
	f.counts[op]++
	if !f.authorizedLocked(r.Header.Get("X-Vault-Token")) {
		f.mu.Unlock()
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	}
	if ft := f.faults[op]; ft != nil && ft.left > 0 {
		ft.left--
		f.mu.Unlock()
		if ft.status == DropConnection {
			hj, ok := w.(http.Hijacker)
			if ok {
				if conn, _, err := hj.Hijack(); err == nil {
					conn.Close()
					return
				}
			}
			writeErr(w, http.StatusBadGateway, "drop not supported")
			return
		}
		writeErr(w, ft.status, "injected fault")
		return
	}
	f.mu.Unlock()

	switch op {
	case OpReadKey:
		f.readKey(w, name)
	case OpCreateKey:
		f.createKey(w, r, name)
	case OpSoftDelete:
		f.softDelete(w, name)
	case OpConfigKey:
		f.configKey(w, r, name)
	case OpHardDelete:
		f.hardDelete(w, name)
	case OpSign:
		f.sign(w, r, name)
	}
}

func (f *Fake) authorizedLocked(token string) bool {
	return token == Token || (token != "" && f.k8sTokens[token])
}

func (f *Fake) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Role string `json:"role"`
		JWT  string `json:"jwt"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	f.counts[OpLogin]++
	if f.k8sRole == "" || req.Role != f.k8sRole || req.JWT == "" {
		f.mu.Unlock()
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	}
	f.k8sSeq++
	tok := "natskeystest-k8s-" + strconv.Itoa(f.k8sSeq)
	f.k8sTokens[tok] = true
	f.mu.Unlock()
	writeJSON(w, map[string]any{"auth": map[string]any{
		"client_token":   tok,
		"lease_duration": 3600,
		"renewable":      true,
	}})
}

func (f *Fake) readKey(w http.ResponseWriter, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.keys[name]
	if k == nil {
		writeJSONStatus(w, http.StatusNotFound, map[string]any{"errors": []string{}})
		return
	}
	versions := map[string]any{}
	for i, priv := range k.versions {
		versions[strconv.Itoa(i+1)] = map[string]any{
			"certificate_chain": "",
			"creation_time":     time.Now().UTC().Format(time.RFC3339Nano),
			"name":              "ed25519",
			"public_key":        base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		}
	}
	data := map[string]any{
		"auto_rotate_period":     0,
		"deletion_allowed":       k.deletionAllowed,
		"keys":                   versions,
		"latest_version":         len(k.versions),
		"min_available_version":  0,
		"min_decryption_version": 1,
		"min_encryption_version": 0,
		"name":                   name,
		"supports_decryption":    false,
		"supports_derivation":    true,
		"supports_encryption":    false,
		"supports_signing":       true,
		"type":                   k.opts.Type,
	}
	if !k.opts.OmitFlags {
		data["exportable"] = k.opts.Exportable
		data["allow_plaintext_backup"] = k.opts.AllowPlaintextBackup
		data["imported_key"] = k.opts.ImportedKey
		data["derived"] = k.opts.Derived
		data["soft_deleted"] = k.opts.SoftDeleted
	}
	writeJSON(w, map[string]any{"data": data})
}

func (f *Fake) createKey(w http.ResponseWriter, r *http.Request, name string) {
	var req struct {
		Type                 string `json:"type"`
		Exportable           bool   `json:"exportable"`
		AllowPlaintextBackup bool   `json:"allow_plaintext_backup"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	if req.Type == "" {
		req.Type = "ed25519"
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keys[name] == nil {
		opts := KeyOptions{Type: req.Type, Exportable: req.Exportable, AllowPlaintextBackup: req.AllowPlaintextBackup}
		f.keys[name] = &key{opts: opts, versions: []ed25519.PrivateKey{priv}}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *Fake) softDelete(w http.ResponseWriter, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.keys[name]
	if k == nil {
		writeErr(w, http.StatusNotFound, "key not found")
		return
	}
	k.opts.SoftDeleted = true
	w.WriteHeader(http.StatusNoContent)
}

// configKey takes deletion_allowed only, as the string "true" or "false"
// or a JSON bool (OpenBao accepts both), and refuses every other field,
// which farmer's policy refuses too. Like OpenBao 2.7.1 it answers 400
// for a key that doesn't exist.
func (f *Fake) configKey(w http.ResponseWriter, r *http.Request, name string) {
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	var allowed bool
	for k, v := range req {
		if k != "deletion_allowed" {
			writeErr(w, http.StatusForbidden, "permission denied")
			return
		}
		switch v {
		case true, "true":
			allowed = true
		case false, "false":
		default:
			writeErr(w, http.StatusBadRequest, "bad deletion_allowed")
			return
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.keys[name]
	if k == nil {
		writeErr(w, http.StatusBadRequest, "no existing key named "+name+" could be found")
		return
	}
	k.deletionAllowed = allowed
	w.WriteHeader(http.StatusNoContent)
}

// hardDelete removes a key whose deletion_allowed is set; like OpenBao
// 2.7.1 it answers 400 for a missing key and for one not allowed to be
// deleted.
func (f *Fake) hardDelete(w http.ResponseWriter, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.keys[name]
	switch {
	case k == nil:
		writeErr(w, http.StatusBadRequest, "error deleting policy "+name+": could not delete key; not found")
	case !k.deletionAllowed:
		writeErr(w, http.StatusBadRequest, "error deleting policy "+name+": deletion is not allowed for this key")
	default:
		delete(f.keys, name)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (f *Fake) sign(w http.ResponseWriter, r *http.Request, name string) {
	var req struct {
		Input      string `json:"input"`
		KeyVersion int    `json:"key_version"`
		BatchInput []struct {
			Input     string `json:"input"`
			Reference string `json:"reference"`
		} `json:"batch_input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad body")
		return
	}
	f.mu.Lock()
	gate, mutate, itemError := f.signGate, f.mutateSignature, f.itemError
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	f.mu.Lock()
	k := f.keys[name]
	if len(req.BatchInput) > 0 {
		f.counts[OpBatch]++
	}
	f.mu.Unlock()
	if k == nil {
		writeErr(w, http.StatusBadRequest, "signing key not found")
		return
	}
	f.mu.Lock()
	softDeleted, n := k.opts.SoftDeleted, len(k.versions)
	f.mu.Unlock()
	if softDeleted {
		writeErr(w, http.StatusBadRequest, "key is soft deleted")
		return
	}
	version := req.KeyVersion
	if version == 0 {
		version = n
	}
	if version < 1 || version > n {
		writeErr(w, http.StatusBadRequest, "invalid key version")
		return
	}
	priv := f.PrivateKey(name, version)
	signOne := func(b64 string) (string, string) {
		input, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return "", "unable to decode input as base64"
		}
		if itemError != nil {
			if msg := itemError(input); msg != "" {
				return "", msg
			}
		}
		sig := fmt.Sprintf("vault:v%d:%s", version, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, input)))
		if mutate != nil {
			sig = mutate(name, version, input, sig)
		}
		return sig, ""
	}
	if len(req.BatchInput) == 0 {
		sig, msg := signOne(req.Input)
		if msg != "" {
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
		writeJSON(w, map[string]any{"data": map[string]any{"signature": sig, "key_version": version}})
		return
	}
	results := make([]map[string]any, len(req.BatchInput))
	for i, item := range req.BatchInput {
		sig, msg := signOne(item.Input)
		res := map[string]any{"reference": item.Reference}
		if msg != "" {
			res["error"] = msg
		} else {
			res["signature"] = sig
		}
		results[i] = res
	}
	writeJSON(w, map[string]any{"data": map[string]any{"batch_results": results}})
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSONStatus(w, status, map[string]any{"errors": []string{msg}})
}

func writeJSON(w http.ResponseWriter, v any) { writeJSONStatus(w, http.StatusOK, v) }

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
