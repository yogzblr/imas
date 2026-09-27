//go:build windows

package winservice

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/yogzblr/imas/internal/log"
)

// Log file limits: sprout.log plus LogKeep rotated files of up to
// LogMaxSize bytes each.
const (
	LogMaxSize = 10 << 20
	LogKeep    = 5
)

// LogToFile sends the logger's output to path, rotated by size, because
// the SCM discards a service's stderr. Go runtime crash output (an
// unrecovered panic, a fatal runtime error), which bypasses the logger, is
// appended to path's "-crash" sibling (sprout.log → sprout-crash.log),
// kept separate because the runtime holds that file open for the life of
// the process, which on Windows would block rotating it. The crash file is
// rotated once at startup if it has grown past LogMaxSize (a crash loop
// restarting every 5s would otherwise grow it without bound).
//
// A failure to set up the crash file is logged, not returned: the log
// file itself is what matters. The returned file is for tests to close.
func LogToFile(path string) (*log.RotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := log.OpenRotatingFile(path, LogMaxSize, LogKeep)
	if err != nil {
		return nil, err
	}
	log.SetOutput(f)

	crashPath := CrashLogPath(path)
	if info, err := os.Stat(crashPath); err == nil && info.Size() >= LogMaxSize {
		if err := log.RotateFile(crashPath, 1); err != nil {
			log.Warnf("cannot rotate %s: %v", crashPath, err)
		}
	}
	crash, err := os.OpenFile(crashPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Warnf("Go crash output stays on stderr, which the SCM discards: %v", err)
		return f, nil
	}
	// SetCrashOutput keeps its own duplicate of the handle.
	defer crash.Close()
	if err := debug.SetCrashOutput(crash, debug.CrashOptions{}); err != nil {
		log.Warnf("Go crash output stays on stderr, which the SCM discards: %v", err)
	}
	return f, nil
}

// CrashLogPath is where LogToFile sends Go crash output for the log at
// path: sprout.log → sprout-crash.log.
func CrashLogPath(path string) string {
	ext := filepath.Ext(path)
	return strings.TrimSuffix(path, ext) + "-crash" + ext
}
