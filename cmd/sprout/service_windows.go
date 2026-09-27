//go:build windows

package main

import (
	"context"

	log "github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/cmd/sprout/internal/winservice"
)

// serviceName is the SCM service the MSI installs
// (packaging/windows/imas-sprout.wxs), named like the systemd unit.
const serviceName = "imas-sprout"

// runAsService runs run under the SCM and reports true when the process
// was started as a Windows service, and reports false otherwise (started
// from a console), leaving run to the caller. It returns once the SCM has
// stopped the service; fatal errors inside run still exit the process
// without reporting SERVICE_STOPPED, so the SCM's failure actions (restart
// after 5s, set by the MSI) apply.
func runAsService(run func(context.Context)) bool {
	isService, err := winservice.IsService()
	if err != nil {
		log.Fatalf("cannot tell whether the sprout runs as a Windows service: %v", err)
	}
	if !isService {
		return false
	}
	if err := winservice.Run(serviceName, run); err != nil {
		log.Fatalf("running as the %s service: %v", serviceName, err)
	}
	return true
}
