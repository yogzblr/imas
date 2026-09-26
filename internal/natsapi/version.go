package natsapi

import (
	"encoding/json"

	"github.com/yogzblr/imas/internal/config"
)

var buildVersion config.Version

// SetBuildVersion sets the version info returned by the version handler.
func SetBuildVersion(v config.Version) {
	buildVersion = v
}

func handleVersion(_ string, _ json.RawMessage) (any, error) {
	return buildVersion, nil
}
