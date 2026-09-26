package props

import (
	"fmt"
	"time"

	log "github.com/yogzblr/imas/internal/log"
)

// StaticPropTTL is the TTL for static props loaded from config.
// Set to ~100 years so they effectively never expire.
const StaticPropTTL = 100 * 365 * 24 * time.Hour

// LoadStaticProps loads static properties from the farmer config.
// Props are organized by sprout ID with key-value pairs.
//
// Expected config structure:
//
//	props:
//	  static:
//	    <sproutID>:
//	      key1: value1
//	      key2: value2
//
// Static props use a very long TTL and are marked Static so
// ClearStaticProps/IsStaticProp can distinguish them from runtime props
// without a separate in-memory index.
func LoadStaticProps(staticCfg map[string]interface{}) {
	if staticCfg == nil {
		return
	}

	loaded := 0
	for sproutID, propsI := range staticCfg {
		propsMap, ok := propsI.(map[string]interface{})
		if !ok {
			log.Errorf("props: static props for sprout %q is not a map", sproutID)
			continue
		}
		for k, v := range propsMap {
			strVal := fmt.Sprintf("%v", v)
			setStaticProp(sproutID, k, strVal)
			loaded++
		}
	}

	if loaded > 0 {
		log.Noticef("props: loaded %d static prop(s) from config", loaded)
	}
}

// setStaticProp sets a prop with the static TTL and the Static flag set.
func setStaticProp(sproutID, name, value string) {
	if sproutID == "" || name == "" {
		return
	}
	upsertProp(propRow{
		TenantID: tenantID(),
		SproutID: sproutID,
		Name:     name,
		Value:    value,
		Static:   true,
		Expiry:   time.Now().Add(StaticPropTTL),
	})
}

// IsStaticProp returns true if the given prop was loaded from config.
func IsStaticProp(sproutID, name string) bool {
	var row propRow
	err := db.Where("tenant_id = ? AND sprout_id = ? AND name = ? AND static = ?",
		tenantID(), sproutID, name, true).First(&row).Error
	return err == nil
}

// ClearStaticProps removes all previously loaded static props for the
// current tenant. Called before reloading config to avoid stale static
// props.
func ClearStaticProps() {
	db.Where("tenant_id = ? AND static = ?", tenantID(), true).Delete(&propRow{})
}
