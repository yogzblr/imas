package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"regexp"
	"sort"
	"strings"

	"github.com/m-mizutani/masq"
)

// Redacted is what replaces a secret in an audit line.
const Redacted = "[REDACTED]"

// maxLoggedParams is the largest params body walked and logged; a larger
// one is logged as its shape only (unparseableShape).
const maxLoggedParams = 1 << 20

// freeFormMethods carry user content (command text, recipes, property
// values, shell requests, public keys): their params are never logged,
// only their shape and hash (freeFormShape). Every other method's params
// are logged with secrets masked (redactParams). Each method maps to the
// top-level keys its handler reads; only those may appear in the shape's
// key list, since any other key name is user text too.
var freeFormMethods = map[string][]string{
	"cmd.run":             {"action", "target"},                                      // command text
	"cook":                {"action", "target"},                                      // recipe name, test flag
	"props.set":           {"name", "sprout_id", "value"},                            // property values
	"shell.open":          {"cli_eph_pub", "idle_timeout_sec", "shell", "sprout_id"}, // shell path, ephemeral key
	"auth.users.add":      {"boxpub", "pubkey", "role", "username"},                  // user's CLI box public key
	"auth.users.resetkey": {"boxpub", "pubkey"},                                      // user's new CLI box public key
	"auth.rotatekey":      {"pub"},                                                   // caller's new CLI box public key
}

// IsFreeForm reports whether action's params are logged as shape and hash
// only.
func IsFreeForm(action string) bool {
	_, ok := freeFormMethods[action]
	return ok
}

// secretKey matches an object key, lower-cased, whose value is a secret:
// a substring match on each word.
var secretKey = regexp.MustCompile(`pass(word|wd|phrase)?|secret|token|api[_-]?key|private|seed|credential|authorization|bearer|cookie|otp|sdb|key_material`)

// secretKeyWords is secretKey's alternation, for the name=value pattern.
const secretKeyWords = `pass(?:word|wd|phrase)?|secret|token|api[_-]?key|private|seed|credential|authorization|bearer|cookie|otp|sdb|key_material`

// stringPatterns are the secrets masked in every string leaf and in
// Entry.Error, applied in order. repl replaces each match.
var stringPatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// A PEM private key block, to its END line (or the end of the string).
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----|.*)`), Redacted},
	// A JWT: three base64url parts, the first a JSON object ("eyJ").
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), Redacted},
	// An NATS seed (user, account, operator, server).
	{regexp.MustCompile(`S[UAON][A-Z2-7]{55}`), Redacted},
	// An AWS access key ID.
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Redacted},
	// A bearer credential.
	{regexp.MustCompile(`(?i)bearer\s+\S+`), Redacted},
	// URL userinfo: scheme://user:pass@host keeps the scheme and host.
	{regexp.MustCompile(`://[^/\s:@]+:[^/\s@]*@`), "://" + Redacted + "@"},
	// name=value or name: value where the name holds a key word, or a
	// command option (-x or --x) holding one followed by whitespace
	// (--password hunter2); the name stays, the value (with an auth scheme
	// before it) goes.
	{regexp.MustCompile(`(?i)([A-Za-z0-9_.-]*(?:` + secretKeyWords + `)[A-Za-z0-9_.-]*"?\s*[=:]\s*|(?:^|\s)--?[A-Za-z0-9_.-]*(?:` + secretKeyWords + `)[A-Za-z0-9_.-]*\s+)(?:(?:basic|digest|bearer)\s+)?("[^"]*"|'[^']*'|[^\s,;&"']+)`), "${1}" + Redacted},
}

// stringMaskers are stringPatterns as masq ReplaceAttr functions, one per
// pattern, applied to a string as a slog attribute.
var stringMaskers = func() []func([]string, slog.Attr) slog.Attr {
	out := make([]func([]string, slog.Attr) slog.Attr, 0, len(stringPatterns))
	for _, p := range stringPatterns {
		p := p
		out = append(out, masq.New(masq.WithRegex(p.re, masq.RedactString(func(s string) string {
			return p.re.ReplaceAllString(s, p.repl)
		}))))
	}
	return out
}()

// RedactString masks every secret stringPatterns finds in s.
func RedactString(s string) string {
	for _, mask := range stringMaskers {
		if v, ok := mask(nil, slog.String("v", s)).Value.Any().(string); ok {
			s = v
		}
	}
	return s
}

// redactEntry returns e with nothing secret left in it: free-form params
// replaced by their shape, other params masked, the error and the targets
// (which can come from params) masked. e itself is not changed.
func redactEntry(e Entry) Entry {
	if len(e.Targets) > 0 {
		targets := make([]string, len(e.Targets))
		for i, t := range e.Targets {
			targets[i] = RedactString(t)
		}
		e.Targets = targets
	}
	if len(e.Parameters) > 0 {
		if known, ok := freeFormMethods[e.Action]; ok {
			e.Parameters = freeFormShape(e.Parameters, known)
		} else {
			e.Parameters = redactParams(e.Parameters)
		}
	}
	if e.Error != "" {
		e.Error = RedactString(e.Error)
	}
	return e
}

// shape is how params that are not logged are described.
type shape struct {
	Redacted string `json:"redacted"`
	Bytes    int    `json:"bytes"`
	SHA256   string `json:"sha256"`
}

// shapeOf is params' shape of the given kind: size and SHA-256.
func shapeOf(kind string, params []byte) shape {
	sum := sha256.Sum256(params)
	return shape{Redacted: kind, Bytes: len(params), SHA256: hex.EncodeToString(sum[:])}
}

// mustJSON marshals v, a value built here from decoded JSON.
func mustJSON(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		// Only strings, numbers, maps and slices reach here.
		panic("audit: " + err.Error())
	}
	return data
}

// freeFormShape describes a free-form method's params: size, hash and the
// sorted top-level key names among known (the method's schema; any other
// key is user text and is left out). Keys is always present, empty when
// params are not a JSON object of at most maxLoggedParams.
func freeFormShape(params json.RawMessage, known []string) json.RawMessage {
	s := shapeOf("free-form", params)
	keys := []string{}
	if len(params) <= maxLoggedParams {
		var m map[string]json.RawMessage
		if json.Unmarshal(params, &m) == nil {
			for _, k := range known {
				if _, ok := m[k]; ok {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
		}
	}
	return mustJSON(struct {
		shape
		Keys []string `json:"keys"`
	}{shape: s, Keys: keys})
}

// unparseableShape describes params that are not JSON or are too large to
// walk.
func unparseableShape(params json.RawMessage) json.RawMessage {
	return mustJSON(shapeOf("unparseable", params))
}

// redactParams masks the secrets in an ordinary method's params: params
// over maxLoggedParams or not JSON become unparseableShape; otherwise every
// value under a secret key name, at any depth, becomes Redacted, and every
// string leaf is masked by RedactString.
func redactParams(params json.RawMessage) json.RawMessage {
	if len(params) > maxLoggedParams || !json.Valid(params) {
		return unparseableShape(params)
	}
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return unparseableShape(params)
	}
	return mustJSON(redactValue(v))
}

// redactValue walks v, a decoded JSON value.
func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if IsSecretKey(k) {
				out[RedactString(k)] = Redacted
				continue
			}
			out[RedactString(k)] = redactValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redactValue(val)
		}
		return out
	case string:
		return RedactString(t)
	default:
		// json.Number, bool, nil.
		return v
	}
}

// IsSecretKey reports whether an object key names a secret.
func IsSecretKey(k string) bool {
	return secretKey.MatchString(strings.ToLower(k))
}
