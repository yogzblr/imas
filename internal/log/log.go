// Package log provides a multiplexed logger for imas that fans out to
// charmbracelet/log (structured terminal output) and log-nats (NATS bus).
// It exposes package-level functions matching the log-socket API for
// drop-in replacement.
package log

import (
	"fmt"
	"os"
	"strings"
	"sync"

	charmlog "github.com/charmbracelet/log"
	nats "github.com/nats-io/nats.go"
	mux "github.com/taigrr/log-mux/log"
	nlog "github.com/taigrr/log-nats/v2/log"
)

var (
	mu     sync.RWMutex
	logger *mux.Logger
	charm  *charmlog.Logger
	natsUp bool
	// borrowedConn is the connection UseNATSConn attached, which belongs
	// to its caller: Flush must not close it. Nil when ConnectNATS dialled
	// (and so owns) the connection, or no NATS backend is attached.
	borrowedConn *nats.Conn
)

func init() {
	charm = charmlog.NewWithOptions(os.Stderr, charmlog.Options{
		ReportTimestamp: true,
		ReportCaller:    true,
	})
	charm.SetLevel(charmlog.DebugLevel)

	logger = mux.Default()
	logger.SubLoggers = append(logger.SubLoggers, newCharmAdapter(charm))
}

// SetLogLevel sets the minimum log level for the charm terminal logger.
// The NATS logger always receives all messages (filtering is done by
// subscribers).
func SetLogLevel(l Level) {
	mu.Lock()
	defer mu.Unlock()
	charm.SetLevel(toCharmLevel(l))
}

// ConnectNATS dials url and connects the NATS logger backend over that
// new, unauthenticated connection, which Flush closes. The NATS logger
// publishes all levels regardless of the terminal log level.
//
// Neither binary uses this any more: a bus in operator mode, or behind
// Envoy, rejects a connection without the caller's User JWT and pinned
// TLS. Prefer UseNATSConn with the connection the caller already holds.
func ConnectNATS(url string) error {
	mu.Lock()
	defer mu.Unlock()
	if natsUp {
		return nil
	}
	if err := nlog.ConnectDefault(url); err != nil {
		return err
	}
	attachNATSLocked()
	return nil
}

// UseNATSConn connects the NATS logger backend over nc, an existing
// connection the caller has already authenticated, instead of dialling a
// new one. Each entry is published to subjectPrefix + "." + its level
// (e.g. "imas.logs.sprouts.web01.INFO"); nc's User JWT must grant publish
// on those subjects, or the bus rejects every entry. All levels are
// published, regardless of the terminal log level.
//
// nc stays the caller's: Flush flushes it but never closes it. Calling
// UseNATSConn again replaces the connection and prefix.
func UseNATSConn(nc *nats.Conn, subjectPrefix string) error {
	if nc == nil {
		return fmt.Errorf("log: UseNATSConn: nil connection")
	}
	if err := validateSubjectPrefix(subjectPrefix); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	// Flush closes whatever connection log-nats holds, so an owned
	// connection must be closed here, before log-nats forgets it.
	if natsUp && borrowedConn == nil {
		nlog.Flush()
	}
	nlog.SetSubjectTemplate(subjectPrefix + ".{{.Level}}")
	nlog.SetDefaultConn(nc)
	borrowedConn = nc
	attachNATSLocked()
	return nil
}

// attachNATSLocked adds the log-nats logger to the mux once. mu must be
// held. It goes after the charm adapter, whose Panic* and Fatal* panic or
// exit first, so log-nats's own Panic*/Fatal* (which close the
// connection, borrowed or not) are never reached.
func attachNATSLocked() {
	if natsUp {
		return
	}
	logger.SubLoggers = append(logger.SubLoggers, nlog.Default())
	natsUp = true
}

// validateSubjectPrefix rejects a prefix that isn't one or more literal
// NATS subject tokens: log entries must land on the subjects the caller's
// JWT grants, never on a wildcard or a malformed subject.
func validateSubjectPrefix(prefix string) error {
	if prefix == "" {
		return fmt.Errorf("log: empty NATS subject prefix")
	}
	for _, tok := range strings.Split(prefix, ".") {
		if tok == "" || tok == "*" || tok == ">" || strings.ContainsAny(tok, " \t\r\n{}") {
			return fmt.Errorf("log: invalid NATS subject prefix %q", prefix)
		}
	}
	return nil
}

// Flush drains any buffered log entries. A connection from ConnectNATS is
// closed; one from UseNATSConn is only flushed, since its owner closes it.
func Flush() {
	mu.RLock()
	nc := borrowedConn
	mu.RUnlock()
	if nc != nil {
		if nc.IsConnected() {
			_ = nc.Flush()
		}
		return
	}
	nlog.Flush()
}

// Package-level logging functions — drop-in replacements for log-socket.

func Trace(args ...any)                 { logger.Trace(args...) }
func Tracef(format string, args ...any) { logger.Tracef(format, args...) }
func Traceln(args ...any)               { logger.Traceln(args...) }

func Debug(args ...any)                 { logger.Debug(args...) }
func Debugf(format string, args ...any) { logger.Debugf(format, args...) }
func Debugln(args ...any)               { logger.Debugln(args...) }

func Info(args ...any)                 { logger.Info(args...) }
func Infof(format string, args ...any) { logger.Infof(format, args...) }
func Infoln(args ...any)               { logger.Infoln(args...) }

func Notice(args ...any)                 { logger.Notice(args...) }
func Noticef(format string, args ...any) { logger.Noticef(format, args...) }
func Noticeln(args ...any)               { logger.Noticeln(args...) }

func Warn(args ...any)                 { logger.Warn(args...) }
func Warnf(format string, args ...any) { logger.Warnf(format, args...) }
func Warnln(args ...any)               { logger.Warnln(args...) }

func Error(args ...any)                 { logger.Error(args...) }
func Errorf(format string, args ...any) { logger.Errorf(format, args...) }
func Errorln(args ...any)               { logger.Errorln(args...) }

func Panic(args ...any)                 { logger.Panic(args...) }
func Panicf(format string, args ...any) { logger.Panicf(format, args...) }
func Panicln(args ...any)               { logger.Panicln(args...) }

func Fatal(args ...any)                 { logger.Fatal(args...) }
func Fatalf(format string, args ...any) { logger.Fatalf(format, args...) }
func Fatalln(args ...any)               { logger.Fatalln(args...) }

func Print(args ...any)                 { logger.Print(args...) }
func Printf(format string, args ...any) { logger.Printf(format, args...) }
func Println(args ...any)               { logger.Println(args...) }
