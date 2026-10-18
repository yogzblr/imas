package props

import (
	"sync"
	"testing"
	"time"
)

func TestSetProp(t *testing.T) {
	newTestDB(t)
	err := setProp(tenantID(), "sprout-1", "key1", "value1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := getStringProp(tenantID(), "sprout-1", "key1")
	if got != "value1" {
		t.Errorf("expected 'value1', got %q", got)
	}
}

func TestSetPropOverwrite(t *testing.T) {
	newTestDB(t)
	setProp(tenantID(), "sprout-1", "key1", "old")
	setProp(tenantID(), "sprout-1", "key1", "new")
	got := getStringProp(tenantID(), "sprout-1", "key1")
	if got != "new" {
		t.Errorf("expected 'new', got %q", got)
	}
}

func TestSetPropEmptySproutID(t *testing.T) {
	newTestDB(t)
	err := setProp(tenantID(), "", "key1", "value1")
	if err != ErrInvalidPropKey {
		t.Errorf("expected ErrInvalidPropKey, got %v", err)
	}
}

func TestSetPropEmptyName(t *testing.T) {
	newTestDB(t)
	err := setProp(tenantID(), "sprout-1", "", "value1")
	if err != ErrInvalidPropKey {
		t.Errorf("expected ErrInvalidPropKey, got %v", err)
	}
}

func TestDeleteProp(t *testing.T) {
	newTestDB(t)
	setProp(tenantID(), "sprout-1", "key1", "value1")
	err := deleteProp(tenantID(), "sprout-1", "key1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := getStringProp(tenantID(), "sprout-1", "key1")
	if got != "" {
		t.Errorf("expected empty string after delete, got %q", got)
	}
}

func TestDeletePropNonExistent(t *testing.T) {
	newTestDB(t)
	err := deleteProp(tenantID(), "sprout-1", "key1")
	if err != nil {
		t.Errorf("expected nil error for deleting non-existent prop, got %v", err)
	}
}

func TestDeletePropEmptySproutID(t *testing.T) {
	newTestDB(t)
	err := deleteProp(tenantID(), "", "key1")
	if err != ErrInvalidPropKey {
		t.Errorf("expected ErrInvalidPropKey, got %v", err)
	}
}

func TestDeletePropEmptyName(t *testing.T) {
	newTestDB(t)
	err := deleteProp(tenantID(), "sprout-1", "")
	if err != ErrInvalidPropKey {
		t.Errorf("expected ErrInvalidPropKey, got %v", err)
	}
}

func TestGetStringPropMissingSprout(t *testing.T) {
	newTestDB(t)
	got := getStringProp(tenantID(), "no-such-sprout", "key1")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestGetStringPropMissingKey(t *testing.T) {
	newTestDB(t)
	setProp(tenantID(), "sprout-1", "key1", "value1")
	got := getStringProp(tenantID(), "sprout-1", "no-such-key")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestGetStringPropExpired(t *testing.T) {
	newTestDB(t)
	setPropWithTTL(tenantID(), "sprout-1", "key1", "value1", 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	got := getStringProp(tenantID(), "sprout-1", "key1")
	if got != "" {
		t.Errorf("expected empty string for expired prop, got %q", got)
	}
}

func TestGetPropsEmpty(t *testing.T) {
	newTestDB(t)
	got := getProps(tenantID(), "no-such-sprout")
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestGetPropsMultiple(t *testing.T) {
	newTestDB(t)
	setProp(tenantID(), "sprout-1", "key1", "value1")
	setProp(tenantID(), "sprout-1", "key2", "value2")
	setProp(tenantID(), "sprout-2", "key3", "value3")

	got := getProps(tenantID(), "sprout-1")
	if len(got) != 2 {
		t.Fatalf("expected 2 props, got %d", len(got))
	}
	if got["key1"] != "value1" {
		t.Errorf("expected 'value1', got %v", got["key1"])
	}
	if got["key2"] != "value2" {
		t.Errorf("expected 'value2', got %v", got["key2"])
	}
}

func TestGetPropsExpiryCleanup(t *testing.T) {
	newTestDB(t)
	setPropWithTTL(tenantID(), "sprout-1", "keep", "yes", 1*time.Hour)
	setPropWithTTL(tenantID(), "sprout-1", "expire", "no", 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	got := getProps(tenantID(), "sprout-1")
	if len(got) != 1 {
		t.Fatalf("expected 1 prop after expiry cleanup, got %d", len(got))
	}
	if got["keep"] != "yes" {
		t.Errorf("expected 'yes', got %v", got["keep"])
	}
}

func TestGetStringPropFuncClosure(t *testing.T) {
	newTestDB(t)
	setProp(tenantID(), "sprout-1", "mykey", "myval")
	fn := GetStringPropFunc("sprout-1")
	got := fn("mykey")
	if got != "myval" {
		t.Errorf("expected 'myval', got %q", got)
	}
}

func TestSetPropFuncClosure(t *testing.T) {
	newTestDB(t)
	fn := SetPropFunc("sprout-1")
	err := fn("key1", "val1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := getStringProp(tenantID(), "sprout-1", "key1")
	if got != "val1" {
		t.Errorf("expected 'val1', got %q", got)
	}
}

func TestDeletePropFuncClosure(t *testing.T) {
	newTestDB(t)
	setProp(tenantID(), "sprout-1", "key1", "value1")
	fn := GetDeletePropFunc("sprout-1")
	err := fn("key1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := getStringProp(tenantID(), "sprout-1", "key1")
	if got != "" {
		t.Errorf("expected empty string after delete, got %q", got)
	}
}

func TestGetPropsFuncClosure(t *testing.T) {
	newTestDB(t)
	setProp(tenantID(), "sprout-1", "a", "1")
	fn := GetPropsFunc("sprout-1")
	got := fn()
	if len(got) != 1 || got["a"] != "1" {
		t.Errorf("expected {a: 1}, got %v", got)
	}
}

func TestConcurrentAccess(t *testing.T) {
	newTestDB(t)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(3)
		go func(n int) {
			defer wg.Done()
			setProp(tenantID(), "sprout-1", "key", "val")
		}(i)
		go func(n int) {
			defer wg.Done()
			getStringProp(tenantID(), "sprout-1", "key")
		}(i)
		go func(n int) {
			defer wg.Done()
			getProps(tenantID(), "sprout-1")
		}(i)
	}
	wg.Wait()
}

func TestIsolationBetweenSprouts(t *testing.T) {
	newTestDB(t)
	setProp(tenantID(), "sprout-a", "shared-key", "alpha")
	setProp(tenantID(), "sprout-b", "shared-key", "beta")

	if got := getStringProp(tenantID(), "sprout-a", "shared-key"); got != "alpha" {
		t.Errorf("sprout-a expected 'alpha', got %q", got)
	}
	if got := getStringProp(tenantID(), "sprout-b", "shared-key"); got != "beta" {
		t.Errorf("sprout-b expected 'beta', got %q", got)
	}

	deleteProp(tenantID(), "sprout-a", "shared-key")
	if got := getStringProp(tenantID(), "sprout-a", "shared-key"); got != "" {
		t.Errorf("sprout-a should be empty after delete, got %q", got)
	}
	if got := getStringProp(tenantID(), "sprout-b", "shared-key"); got != "beta" {
		t.Errorf("sprout-b should still be 'beta', got %q", got)
	}
}
