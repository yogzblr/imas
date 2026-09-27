//go:build windows

package main

import (
	"context"
	"path/filepath"

	log "github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/cmd/sprout/internal/winservice"
	"github.com/yogzblr/imas/internal/config"
)

// serviceName is the SCM service the MSI installs
// (packaging/windows/imas-sprout.wxs), named like the systemd unit.
const serviceName = "imas-sprout"

// isService records, before init runs, whether the SCM started this
// process. A detection error is reported by runAsService.
var isService, isServiceErr = winservice.IsService()

// startServiceLog sends logs to %ProgramData%\imas\logs\sprout.log when
// the SCM started the process, since the SCM discards stderr. A console
// run keeps logging to stderr. If the file can't be opened there is
// nowhere to report it, so logs stay on stderr.
func startServiceLog() {
	if isServiceErr != nil || !isService {
		return
	}
	_, _ = winservice.LogToFile(filepath.Join(config.SproutServiceLogDir(), "sprout.log"))
}

// runAsService runs run under the SCM and reports true when the process
// was started as a Windows service, and reports false otherwise (started
// from a console), leaving run to the caller. It returns once the SCM has
// stopped the service; fatal errors inside run still exit the process
// without reporting SERVICE_STOPPED, so the SCM's failure actions (restart
// after 5s, set by the MSI) apply.
func runAsService(run func(context.Context)) bool {
	if isServiceErr != nil {
		log.Fatalf("cannot tell whether the sprout runs as a Windows service: %v", isServiceErr)
	}
	if !isService {
		return false
	}
	if err := winservice.Run(serviceName, run); err != nil {
		log.Fatalf("running as the %s service: %v", serviceName, err)
	}
	return true
}
