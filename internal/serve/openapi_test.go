package serve

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// loadSpec parses the embedded OpenAPI document.
func loadSpec(t *testing.T) map[string]any {
	t.Helper()
	var spec map[string]any
	if err := yaml.Unmarshal(openapiSpec, &spec); err != nil {
		t.Fatalf("openapi.yaml does not parse: %v", err)
	}
	return spec
}

// resolveRef follows a local JSON pointer ("#/a/b") through spec.
func resolveRef(spec map[string]any, ref string) (any, error) {
	path, ok := strings.CutPrefix(ref, "#/")
	if !ok {
		return nil, fmt.Errorf("non-local $ref %q", ref)
	}
	var node any = spec
	for _, seg := range strings.Split(path, "/") {
		seg = strings.ReplaceAll(strings.ReplaceAll(seg, "~1", "/"), "~0", "~")
		m, ok := node.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("$ref %q: %q is not under an object", ref, seg)
		}
		if node, ok = m[seg]; !ok {
			return nil, fmt.Errorf("$ref %q: no %q", ref, seg)
		}
	}
	return node, nil
}

// walk calls fn on every object in node, depth first, with its path.
func walk(node any, path string, fn func(path string, m map[string]any)) {
	switch v := node.(type) {
	case map[string]any:
		fn(path, v)
		for k, c := range v {
			walk(c, path+"/"+k, fn)
		}
	case []any:
		for i, c := range v {
			walk(c, fmt.Sprintf("%s/%d", path, i), fn)
		}
	}
}

// The spec stays a well-formed OpenAPI 3.1 document: every $ref resolves,
// every operation has a unique operationId and responses, and every
// schema's required fields are among its properties.
func TestOpenAPISpecValidates(t *testing.T) {
	spec := loadSpec(t)
	if v, _ := spec["openapi"].(string); !strings.HasPrefix(v, "3.1.") {
		t.Fatalf("openapi = %q, want 3.1.x", v)
	}
	info, _ := spec["info"].(map[string]any)
	if info["title"] == nil || info["version"] == nil {
		t.Error("info needs title and version")
	}
	paths, _ := spec["paths"].(map[string]any)
	if len(paths) == 0 {
		t.Fatal("no paths")
	}

	walk(spec, "#", func(path string, m map[string]any) {
		if ref, ok := m["$ref"].(string); ok {
			if _, err := resolveRef(spec, ref); err != nil {
				t.Errorf("%s: %v", path, err)
			}
		}
		req, hasReq := m["required"].([]any)
		props, hasProps := m["properties"].(map[string]any)
		if hasReq && hasProps {
			for _, r := range req {
				if _, ok := props[r.(string)]; !ok {
					t.Errorf("%s: required %q is not a property", path, r)
				}
			}
		}
	})

	methods := []string{"get", "put", "post", "delete", "patch", "head", "options"}
	seen := map[string]string{}
	for p, item := range paths {
		if !strings.HasPrefix(p, "/") {
			t.Errorf("path %q does not start with /", p)
		}
		ops, _ := item.(map[string]any)
		for _, method := range methods {
			op, ok := ops[method].(map[string]any)
			if !ok {
				continue
			}
			id, _ := op["operationId"].(string)
			if id == "" {
				t.Errorf("%s %s: no operationId", method, p)
			} else if prev, dup := seen[id]; dup {
				t.Errorf("operationId %q used by %s and %s %s", id, prev, method, p)
			}
			seen[id] = method + " " + p
			if r, _ := op["responses"].(map[string]any); len(r) == 0 {
				t.Errorf("%s %s: no responses", method, p)
			}
		}
	}
}

// POST /api/v1/auth/users documents boxpub as farmer's auth.users.add
// takes it: a required field, alongside the optional username.
func TestOpenAPIUserAddRequestHasBoxPub(t *testing.T) {
	spec := loadSpec(t)
	op, err := resolveRef(spec, "#/paths/~1api~1v1~1auth~1users/post/requestBody/content/application~1json/schema/$ref")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := resolveRef(spec, op.(string))
	if err != nil {
		t.Fatal(err)
	}
	s := schema.(map[string]any)
	props := s["properties"].(map[string]any)
	for _, f := range []string{"pubkey", "role", "username", "boxpub"} {
		if _, ok := props[f]; !ok {
			t.Errorf("UserAddRequest has no %q", f)
		}
	}
	var required []string
	for _, r := range s["required"].([]any) {
		required = append(required, r.(string))
	}
	for _, f := range []string{"pubkey", "role", "boxpub"} {
		if !slices.Contains(required, f) {
			t.Errorf("UserAddRequest.required = %v, missing %q", required, f)
		}
	}
}
