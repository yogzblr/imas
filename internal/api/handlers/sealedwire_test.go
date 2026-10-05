package handlers

// What a sealed answer on the wire may and may not show (T.1). Checking
// a sealed body for a substring such as "eyJ" is wrong: it is random
// standard base64 ciphertext, which contains any short substring by
// chance (1.5% of runs for "eyJ"). Instead the body must decode as exactly
// the sealed shape, so its only plaintext is that shape's field names,
// and no key or string anywhere in it may be or contain a JWT.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/payloadbox"
)

// sealedWireEnvelope is payloadbox.Envelope with the copies' byte fields,
// which encoding/json decodes as standard base64.
type sealedWireEnvelope struct {
	V      int `json:"v"`
	Copies []struct {
		Nonce []byte `json:"n"`
		Box   []byte `json:"c"`
	} `json:"s"`
}

// decodeStrict decodes data into v, refusing unknown fields and trailing
// data.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

// checkSealedEnvelope reports whether raw is exactly a payloadbox
// envelope: version, and copies of a 24-byte nonce and a box no shorter
// than its tag, with no other field.
func checkSealedEnvelope(raw []byte) error {
	var env sealedWireEnvelope
	if err := decodeStrict(raw, &env); err != nil {
		return fmt.Errorf("not a sealed envelope: %w", err)
	}
	if env.V != payloadbox.Version || len(env.Copies) == 0 || len(env.Copies) > payloadbox.MaxCopies {
		return fmt.Errorf("envelope v=%d with %d copies", env.V, len(env.Copies))
	}
	for i, c := range env.Copies {
		if len(c.Nonce) != 24 || len(c.Box) < box.Overhead {
			return fmt.Errorf("copy %d: %d-byte nonce, %d-byte box", i, len(c.Nonce), len(c.Box))
		}
	}
	return nil
}

// jsonKeysAndStrings returns every object key and string value in data,
// in order and including duplicated keys, which a map would drop.
func jsonKeysAndStrings(data []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var out []string
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if s, ok := tok.(string); ok {
			out = append(out, s)
		}
	}
}

// findJWT returns the first JWT in s: three dot-separated base64url parts
// (a JWS; a JWE's first three parts match too) whose first part decodes
// to a JSON object, its header. Standard base64 has no '.', so ciphertext
// never matches by chance.
func findJWT(s string) (string, bool) {
	isPart := func(r rune) bool {
		return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '='
	}
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r != '.' && !isPart(r) }) {
		parts := strings.Split(tok, ".")
		for i := 0; i+2 < len(parts); i++ {
			if parts[i+1] == "" {
				continue
			}
			hdr, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[i], "="))
			var obj map[string]json.RawMessage
			if err == nil && json.Unmarshal(hdr, &obj) == nil {
				return strings.Join(parts[i:i+3], "."), true
			}
		}
	}
	return "", false
}

// jwtInJSON returns the first JWT in any key or string value of data.
func jwtInJSON(data []byte) (string, bool, error) {
	strs, err := jsonKeysAndStrings(data)
	if err != nil {
		return "", false, err
	}
	for _, s := range strs {
		if jwt, ok := findJWT(s); ok {
			return jwt, true, nil
		}
	}
	return "", false, nil
}
