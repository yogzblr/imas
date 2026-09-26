package cook

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/props"
)

// TestPropsInFileBasedRecipe verifies the full file-based pipeline:
// write a recipe with props to the recipe store → collectAllIncludes
// resolves it → props render in the final step extraction.
func TestPropsInFileBasedRecipe(t *testing.T) {
	props.ClearStaticProps()

	// Set dynamic props for the sprout.
	props.SetProp("file-sprout", "app_user", "webadmin")
	props.SetProp("file-sprout", "app_port", "9090")

	// Create the recipe in a fresh, test-scoped recipe store.
	recipeDir := newRecipeTestStore(t)

	recipeContent := `steps:
  deploy config:
    file.managed:
      - name: /etc/myapp/config.yml
      - user: {{ props "app_user" }}
      - mode: "644"
  start app:
    cmd.run:
      - name: "myapp --port={{ props "app_port" }}"
      - requisites:
        - require: deploy config
`
	recipeFile := filepath.Join(recipeDir, "deploy.imas")
	writeRecipe(t, recipeFile, recipeContent)

	// Collect includes (which also renders templates).
	includes, err := collectAllIncludes(context.Background(), testPropsTenantID, "file-sprout", recipeDir, "deploy")
	if err != nil {
		t.Fatalf("collectAllIncludes: %v", err)
	}
	if len(includes) != 1 {
		t.Fatalf("expected 1 include, got %d: %v", len(includes), includes)
	}

	// Read and render the recipe.
	f := mustReadRecipe(t, recipeFile)

	rendered, err := renderRecipeTemplate(testPropsTenantID, "file-sprout", recipeFile, f)
	if err != nil {
		t.Fatalf("renderRecipeTemplate: %v", err)
	}

	// Parse into steps.
	recipeMap, err := unmarshalRecipe(rendered)
	if err != nil {
		t.Fatalf("unmarshalRecipe: %v", err)
	}
	stepsMap, err := stepsFromMap(recipeMap)
	if err != nil {
		t.Fatalf("stepsFromMap: %v", err)
	}
	steps, err := makeRecipeSteps(stepsMap)
	if err != nil {
		t.Fatalf("makeRecipeSteps: %v", err)
	}

	if len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(steps))
	}

	// Verify props resolved in rendered output.
	renderedStr := string(rendered)
	if !strings.Contains(renderedStr, "user: webadmin") {
		t.Errorf("expected 'user: webadmin' in rendered output, got:\n%s", renderedStr)
	}
	if !strings.Contains(renderedStr, "--port=9090") {
		t.Errorf("expected '--port=9090' in rendered output, got:\n%s", renderedStr)
	}
}

// TestPropsInRecipeWithIncludes verifies that props resolve correctly
// in recipes that include other recipes.
func TestPropsInRecipeWithIncludes(t *testing.T) {
	props.ClearStaticProps()
	props.SetProp("include-sprout", "db_host", "db.internal")
	props.SetProp("include-sprout", "cache_host", "redis.internal")

	recipeDir := newRecipeTestStore(t)

	// Base recipe that's included.
	baseContent := `steps:
  configure db:
    file.managed:
      - name: /etc/app/db.conf
      - source: imas://configs/db.conf
      - user: root
`
	baseFile := filepath.Join(recipeDir, "base.imas")
	writeRecipe(t, baseFile, baseContent)

	// Main recipe with include and props.
	mainContent := `include:
  - base

steps:
  configure cache:
    file.managed:
      - name: /etc/app/cache.conf
      - source: imas://configs/cache.conf
      - user: {{ props "db_host" }}
`
	mainFile := filepath.Join(recipeDir, "main.imas")
	writeRecipe(t, mainFile, mainContent)

	includes, err := collectAllIncludes(context.Background(), testPropsTenantID, "include-sprout", recipeDir, "main")
	if err != nil {
		t.Fatalf("collectAllIncludes: %v", err)
	}

	// Should have both main and base.
	if len(includes) != 2 {
		t.Fatalf("expected 2 includes, got %d: %v", len(includes), includes)
	}

	// Render main recipe and verify props resolved.
	f := mustReadRecipe(t, mainFile)
	rendered, err := renderRecipeTemplate(testPropsTenantID, "include-sprout", mainFile, f)
	if err != nil {
		t.Fatalf("renderRecipeTemplate: %v", err)
	}

	if !strings.Contains(string(rendered), "user: db.internal") {
		t.Errorf("expected props to resolve in included recipe, got:\n%s", string(rendered))
	}
}

// TestStaticPropsInFileBasedRecipe verifies static props (from farmer
// config) work through the file-based pipeline.
func TestStaticPropsInFileBasedRecipe(t *testing.T) {
	props.ClearStaticProps()

	cfg := map[string]interface{}{
		"static-file-sprout": map[string]interface{}{
			"cluster": "prod-us-east",
			"tier":    "frontend",
		},
	}
	props.LoadStaticProps(cfg)
	t.Cleanup(props.ClearStaticProps)

	recipeDir := newRecipeTestStore(t)

	recipeContent := `steps:
  tag node:
    cmd.run:
      - name: "node-tagger --cluster={{ props "cluster" }} --tier={{ props "tier" }}"
`
	recipeFile := filepath.Join(recipeDir, "tagging.imas")
	writeRecipe(t, recipeFile, recipeContent)

	f := mustReadRecipe(t, recipeFile)
	rendered, err := renderRecipeTemplate(testPropsTenantID, "static-file-sprout", recipeFile, f)
	if err != nil {
		t.Fatalf("renderRecipeTemplate: %v", err)
	}

	renderedStr := string(rendered)
	if !strings.Contains(renderedStr, "--cluster=prod-us-east") {
		t.Errorf("expected static prop cluster resolved, got:\n%s", renderedStr)
	}
	if !strings.Contains(renderedStr, "--tier=frontend") {
		t.Errorf("expected static prop tier resolved, got:\n%s", renderedStr)
	}

	// Parse all the way to steps.
	recipeMap, _ := unmarshalRecipe(rendered)
	stepsMap, _ := stepsFromMap(recipeMap)
	steps, err := makeRecipeSteps(stepsMap)
	if err != nil {
		t.Fatalf("makeRecipeSteps: %v", err)
	}
	if len(steps) != 1 {
		t.Fatalf("expected 1 step, got %d", len(steps))
	}
	if steps[0].Properties["name"] != "node-tagger --cluster=prod-us-east --tier=frontend" {
		t.Errorf("step name not fully resolved: %v", steps[0].Properties["name"])
	}
}

// TestPropsWithHostnameAndSproutIDInFile verifies the hostname and
// sproutID template functions work in file-based recipes.
func TestPropsWithHostnameAndSproutIDInFile(t *testing.T) {
	recipeDir := newRecipeTestStore(t)

	recipeContent := `steps:
  set banner:
    file.managed:
      - name: /etc/motd
      - text: "Host {{ hostname }} managed by sprout {{ sproutID }}"
`
	recipeFile := filepath.Join(recipeDir, "banner.imas")
	writeRecipe(t, recipeFile, recipeContent)

	f := mustReadRecipe(t, recipeFile)
	rendered, err := renderRecipeTemplate(testPropsTenantID, "banner-sprout-42", recipeFile, f)
	if err != nil {
		t.Fatalf("renderRecipeTemplate: %v", err)
	}

	renderedStr := string(rendered)
	if strings.Contains(renderedStr, "{{ hostname }}") {
		t.Error("hostname template was not resolved")
	}
	if !strings.Contains(renderedStr, "banner-sprout-42") {
		t.Errorf("expected sproutID in output, got:\n%s", renderedStr)
	}
}

// TestPropsWithConditionalInclude verifies that a conditional block
// controlled by props can gate whether recipe steps are present after
// the full file pipeline.
func TestPropsWithConditionalInclude(t *testing.T) {
	props.ClearStaticProps()

	recipeDir := newRecipeTestStore(t)

	recipeContent := `steps:
  base:
    cmd.run:
      - name: echo base
{{- if (props "enable_monitoring") }}
  monitoring:
    file.managed:
      - name: /etc/monitoring.conf
      - source: imas://monitoring/config
{{- end }}
`
	recipeFile := filepath.Join(recipeDir, "conditional.imas")
	writeRecipe(t, recipeFile, recipeContent)

	// Without the prop — only 1 step.
	f := mustReadRecipe(t, recipeFile)
	rendered, err := renderRecipeTemplate(testPropsTenantID, "cond-sprout-off", recipeFile, f)
	if err != nil {
		t.Fatalf("render (off): %v", err)
	}
	recipeMap, _ := unmarshalRecipe(rendered)
	stepsMap, _ := stepsFromMap(recipeMap)
	if len(stepsMap) != 1 {
		t.Fatalf("expected 1 step without prop, got %d", len(stepsMap))
	}

	// With the prop — 2 steps.
	props.SetProp("cond-sprout-on", "enable_monitoring", "true")
	rendered, err = renderRecipeTemplate(testPropsTenantID, "cond-sprout-on", recipeFile, f)
	if err != nil {
		t.Fatalf("render (on): %v", err)
	}
	recipeMap, _ = unmarshalRecipe(rendered)
	stepsMap, _ = stepsFromMap(recipeMap)
	if len(stepsMap) != 2 {
		t.Fatalf("expected 2 steps with prop, got %d", len(stepsMap))
	}
}

// TestPropsWithDefaultFallbackInFile verifies the default template
// function works correctly in file-based recipes.
func TestPropsWithDefaultFallbackInFile(t *testing.T) {
	props.ClearStaticProps()
	props.SetProp("default-sprout", "custom_port", "3000")

	recipeDir := newRecipeTestStore(t)

	recipeContent := `steps:
  configure:
    cmd.run:
      - name: "app --port={{ default "8080" (props "custom_port") }} --host={{ default "localhost" (props "custom_host") }}"
`
	recipeFile := filepath.Join(recipeDir, "defaults.imas")
	writeRecipe(t, recipeFile, recipeContent)

	f := mustReadRecipe(t, recipeFile)
	rendered, err := renderRecipeTemplate(testPropsTenantID, "default-sprout", recipeFile, f)
	if err != nil {
		t.Fatalf("renderRecipeTemplate: %v", err)
	}

	renderedStr := string(rendered)
	if !strings.Contains(renderedStr, "--port=3000") {
		t.Errorf("expected custom port 3000 (not default), got:\n%s", renderedStr)
	}
	if !strings.Contains(renderedStr, "--host=localhost") {
		t.Errorf("expected default host localhost, got:\n%s", renderedStr)
	}
}

// TestMultiSproutSameRecipeFile verifies that the same recipe file
// renders differently for different sprouts based on their props.
func TestMultiSproutSameRecipeFile(t *testing.T) {
	props.ClearStaticProps()

	cfg := map[string]interface{}{
		"web-node":    map[string]interface{}{"role": "webserver", "port": "80"},
		"api-node":    map[string]interface{}{"role": "api", "port": "8080"},
		"worker-node": map[string]interface{}{"role": "worker", "port": "0"},
	}
	props.LoadStaticProps(cfg)
	t.Cleanup(props.ClearStaticProps)

	recipeDir := newRecipeTestStore(t)

	recipeContent := `steps:
  configure:
    cmd.run:
      - name: "setup --role={{ props "role" }} --port={{ props "port" }}"
`
	recipeFile := filepath.Join(recipeDir, "setup.imas")
	writeRecipe(t, recipeFile, recipeContent)

	f := mustReadRecipe(t, recipeFile)

	type testCase struct {
		sproutID     string
		expectedRole string
		expectedPort string
	}

	cases := []testCase{
		{"web-node", "webserver", "80"},
		{"api-node", "api", "8080"},
		{"worker-node", "worker", "0"},
	}

	for _, tc := range cases {
		t.Run(tc.sproutID, func(t *testing.T) {
			rendered, err := renderRecipeTemplate(testPropsTenantID, tc.sproutID, recipeFile, f)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			renderedStr := string(rendered)
			if !strings.Contains(renderedStr, "--role="+tc.expectedRole) {
				t.Errorf("expected role=%s, got:\n%s", tc.expectedRole, renderedStr)
			}
			if !strings.Contains(renderedStr, "--port="+tc.expectedPort) {
				t.Errorf("expected port=%s, got:\n%s", tc.expectedPort, renderedStr)
			}
		})
	}
}
