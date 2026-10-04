package props

import (
	"errors"
	"os"
	"time"
)

// DefaultPropTTL is the default time-to-live for properties.
const DefaultPropTTL = 5 * time.Minute

// ErrInvalidPropKey is returned when a sproutID or property name is empty.
var ErrInvalidPropKey = errors.New("sproutID and property name must not be empty")

func GetStringPropFunc(sproutID string) func(string) string {
	return func(name string) string {
		return getStringProp(tenantID(), sproutID, name)
	}
}

// GetStringPropFuncForTenant is GetStringPropFunc scoped to an explicit
// tenant instead of the package's current-tenant seam — used by
// internal/rbac/cohort.go's dynamic-cohort resolution, which has a real
// per-Registry tenant to pass. See
// docs/design/imas-tenant-context-threading.md.
func GetStringPropFuncForTenant(tenantID, sproutID string) func(string) string {
	return func(name string) string {
		return getStringProp(tenantID, sproutID, name)
	}
}

// GetStringProp returns the string value of a single property for a sprout.
// Returns an empty string if the sprout or property does not exist, or if the
// property has expired.
func GetStringProp(sproutID, name string) string {
	return getStringProp(tenantID(), sproutID, name)
}

// GetStringPropForTenant is GetStringProp scoped to an explicit tenant
// instead of the package's current-tenant seam.
func GetStringPropForTenant(tenantID, sproutID, name string) string {
	return getStringProp(tenantID, sproutID, name)
}

func getStringProp(tenantID, sproutID, name string) string {
	var row propRow
	err := db.Where("tenant_id = ? AND sprout_id = ? AND name = ? AND expiry > ?",
		tenantID, sproutID, name, time.Now()).First(&row).Error
	if err != nil {
		return ""
	}
	return row.Value
}

func SetPropFunc(sproutID string) func(string, string) error {
	return func(name, value string) error {
		return setProp(tenantID(), sproutID, name, value)
	}
}

// SetProp sets a property for a sprout with the default TTL.
func SetProp(sproutID, name, value string) error {
	return setProp(tenantID(), sproutID, name, value)
}

// SetPropForTenant is SetProp scoped to an explicit tenant instead of the
// package's current-tenant seam.
func SetPropForTenant(tenantID, sproutID, name, value string) error {
	return setProp(tenantID, sproutID, name, value)
}

// SetPropForTenantWithTTL is SetPropForTenant with an explicit time to
// live instead of DefaultPropTTL. internal/facts uses it for the hostname
// fact (facts.HostnamePropTTL).
func SetPropForTenantWithTTL(tenantID, sproutID, name, value string, ttl time.Duration) error {
	return setPropWithTTL(tenantID, sproutID, name, value, ttl)
}

func setProp(tenantID, sproutID, name, value string) error {
	return setPropWithTTL(tenantID, sproutID, name, value, DefaultPropTTL)
}

func setPropWithTTL(tenantID, sproutID, name, value string, ttl time.Duration) error {
	if sproutID == "" || name == "" {
		return ErrInvalidPropKey
	}
	return upsertProp(propRow{
		TenantID: tenantID,
		SproutID: sproutID,
		Name:     name,
		Value:    value,
		Expiry:   time.Now().Add(ttl),
	})
}

func GetDeletePropFunc(sproutID string) func(string) error {
	return func(name string) error {
		return deleteProp(tenantID(), sproutID, name)
	}
}

// DeleteProp removes a property for a sprout. Returns nil if the property
// does not exist.
func DeleteProp(sproutID, name string) error {
	return deleteProp(tenantID(), sproutID, name)
}

// DeletePropForTenant is DeleteProp scoped to an explicit tenant instead of
// the package's current-tenant seam.
func DeletePropForTenant(tenantID, sproutID, name string) error {
	return deleteProp(tenantID, sproutID, name)
}

func deleteProp(tenantID, sproutID, name string) error {
	if sproutID == "" || name == "" {
		return ErrInvalidPropKey
	}
	return db.Where("tenant_id = ? AND sprout_id = ? AND name = ?",
		tenantID, sproutID, name).Delete(&propRow{}).Error
}

func GetPropsFunc(sproutID string) func() map[string]interface{} {
	return func() map[string]interface{} {
		return getProps(tenantID(), sproutID)
	}
}

// GetProps returns all non-expired properties for a sprout. Returns nil if the
// sprout has no properties.
func GetProps(sproutID string) map[string]interface{} {
	return getProps(tenantID(), sproutID)
}

// GetPropsForTenant is GetProps scoped to an explicit tenant instead of the
// package's current-tenant seam.
func GetPropsForTenant(tenantID, sproutID string) map[string]interface{} {
	return getProps(tenantID, sproutID)
}

func getProps(tenantID, sproutID string) map[string]interface{} {
	var rows []propRow
	if err := db.Where("tenant_id = ? AND sprout_id = ? AND expiry > ?",
		tenantID, sproutID, time.Now()).Find(&rows).Error; err != nil || len(rows) == 0 {
		return nil
	}
	result := make(map[string]interface{}, len(rows))
	for _, r := range rows {
		result[r.Name] = r.Value
	}
	return result
}

func GetHostnameFunc(sproutID string) func() string {
	return func() string {
		return hostname(sproutID)
	}
}

// GetHostnameFuncForTenant is GetHostnameFunc scoped to an explicit tenant
// instead of the package's current-tenant seam — see
// GetStringPropFuncForTenant.
func GetHostnameFuncForTenant(tenantID, sproutID string) func() string {
	return func() string {
		return hostname(sproutID)
	}
}

func hostname(sproutID string) string {
	hostname, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	return hostname
}
