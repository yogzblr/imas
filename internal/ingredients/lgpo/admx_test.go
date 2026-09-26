package lgpo

import "testing"

func TestLoadADMXExampleFixture(t *testing.T) {
	policies, err := LoadADMX("testdata/example.admx")
	if err != nil {
		t.Fatalf("LoadADMX() error: %v", err)
	}
	if len(policies) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(policies))
	}

	res, err := LoadADML("testdata/en-us/example.adml")
	if err != nil {
		t.Fatalf("LoadADML() error: %v", err)
	}

	boolPolicy, err := FindPolicy(policies, "ExampleBoolean", res)
	if err != nil {
		t.Fatalf("FindPolicy() error: %v", err)
	}
	if boolPolicy.DisplayName != "Example Boolean Policy" {
		t.Errorf("DisplayName = %q, want resolved ADML text", boolPolicy.DisplayName)
	}
	if boolPolicy.Key != `Software\Policies\Imas\Example` || boolPolicy.ValueName != "EnableFeature" {
		t.Errorf("unexpected key/valueName: %q %q", boolPolicy.Key, boolPolicy.ValueName)
	}
	if boolPolicy.EnabledValue == nil || boolPolicy.EnabledValue.Decimal == nil || *boolPolicy.EnabledValue.Decimal != 1 {
		t.Errorf("EnabledValue = %+v, want decimal 1", boolPolicy.EnabledValue)
	}
	if boolPolicy.DisabledValue == nil || boolPolicy.DisabledValue.Decimal == nil || *boolPolicy.DisabledValue.Decimal != 0 {
		t.Errorf("DisabledValue = %+v, want decimal 0", boolPolicy.DisabledValue)
	}
}

func TestFindPolicyWithoutADML(t *testing.T) {
	policies, err := LoadADMX("testdata/example.admx")
	if err != nil {
		t.Fatalf("LoadADMX() error: %v", err)
	}
	p, err := FindPolicy(policies, "ExampleBoolean", nil)
	if err != nil {
		t.Fatalf("FindPolicy() error: %v", err)
	}
	if p.DisplayName != "$(string.ExampleBoolean)" {
		t.Errorf("expected unresolved reference without ADML, got %q", p.DisplayName)
	}
}

func TestFindPolicyNotFound(t *testing.T) {
	policies, err := LoadADMX("testdata/example.admx")
	if err != nil {
		t.Fatalf("LoadADMX() error: %v", err)
	}
	if _, err := FindPolicy(policies, "DoesNotExist", nil); err == nil {
		t.Fatal("expected an error for an unknown policy name")
	}
}

func TestListPolicyResolution(t *testing.T) {
	policies, err := LoadADMX("testdata/example.admx")
	if err != nil {
		t.Fatalf("LoadADMX() error: %v", err)
	}
	p, err := FindPolicy(policies, "ExampleList", nil)
	if err != nil {
		t.Fatalf("FindPolicy() error: %v", err)
	}
	if len(p.EnabledList) != 2 || len(p.DisabledList) != 2 {
		t.Fatalf("EnabledList/DisabledList = %d/%d, want 2/2", len(p.EnabledList), len(p.DisabledList))
	}
	for _, it := range p.EnabledList {
		if it.Key != `Software\Policies\Imas\Example` {
			t.Errorf("list item key = %q, want defaultKey to apply", it.Key)
		}
	}
	if p.EnabledList[1].Value.Text == nil || *p.EnabledList[1].Value.Text != "enabled-b" {
		t.Errorf("EnabledList[1] = %+v, want string enabled-b", p.EnabledList[1].Value)
	}
}

func TestElementsParsing(t *testing.T) {
	policies, err := LoadADMX("testdata/example.admx")
	if err != nil {
		t.Fatalf("LoadADMX() error: %v", err)
	}
	p, err := FindPolicy(policies, "ExampleElements", nil)
	if err != nil {
		t.Fatalf("FindPolicy() error: %v", err)
	}
	if len(p.Elements) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(p.Elements))
	}
	kinds := map[string]ElementKind{}
	required := map[string]bool{}
	for _, e := range p.Elements {
		kinds[e.ID] = e.Kind
		required[e.ID] = e.Required
		if e.Key != p.Key {
			t.Errorf("element %q key = %q, want policy default %q", e.ID, e.Key, p.Key)
		}
	}
	if kinds["MyBool"] != ElementBoolean || kinds["MyNum"] != ElementDecimal || kinds["MyText"] != ElementText {
		t.Errorf("unexpected element kinds: %+v", kinds)
	}
	if !required["MyNum"] || required["MyText"] {
		t.Errorf("unexpected required flags: %+v", required)
	}
}

func TestResourcesResolveUnknownRef(t *testing.T) {
	res, err := LoadADML("testdata/en-us/example.adml")
	if err != nil {
		t.Fatalf("LoadADML() error: %v", err)
	}
	if got := res.Resolve("$(string.NoSuchID)"); got != "$(string.NoSuchID)" {
		t.Errorf("Resolve() = %q, want the reference unchanged", got)
	}
	if got := res.Resolve("already plain text"); got != "already plain text" {
		t.Errorf("Resolve() = %q, want unchanged", got)
	}
	var nilRes *Resources
	if got := nilRes.Resolve("$(string.TestCategory)"); got != "$(string.TestCategory)" {
		t.Errorf("nil Resources.Resolve() = %q, want the reference unchanged", got)
	}
}

func TestLoadADMXMissingFile(t *testing.T) {
	if _, err := LoadADMX("testdata/does-not-exist.admx"); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}
