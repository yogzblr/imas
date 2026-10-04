package log

import (
	"fmt"
	"strings"
	"sync/atomic"

	mux "github.com/taigrr/log-mux/log"
)

// DefaultNATSMinLevel is the lowest level shipped over NATS unless
// SetNATSMinLevel says otherwise. Trace and Debug stay local: log
// shipping is plaintext on the bus, and debug output is where request
// detail tends to end up (security review 2026-10, H4).
const DefaultNATSMinLevel = LInfo

// natsMinLevel is the lowest Level natsSink passes on.
var natsMinLevel atomic.Int32

func init() { natsMinLevel.Store(int32(DefaultNATSMinLevel)) }

// SetNATSMinLevel sets the lowest level the NATS backend publishes.
// Entries below it are dropped before they reach log-nats, which itself
// publishes every entry it is given. Panic and Fatal always pass.
func SetNATSMinLevel(l Level) {
	natsMinLevel.Store(int32(min(max(l, LTrace), LFatal)))
}

// NATSMinLevel returns the lowest level the NATS backend publishes.
func NATSMinLevel() Level { return Level(natsMinLevel.Load()) }

// ParseLevel parses a level name (trace, debug, info, notice, warn or
// warning, error, panic, fatal; any case).
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace":
		return LTrace, nil
	case "debug":
		return LDebug, nil
	case "info":
		return LInfo, nil
	case "notice":
		return LNotice, nil
	case "warn", "warning":
		return LWarn, nil
	case "error":
		return LError, nil
	case "panic":
		return LPanic, nil
	case "fatal":
		return LFatal, nil
	}
	return LInfo, fmt.Errorf("log: unknown level %q", s)
}

// natsSink passes entries at or above natsMinLevel to the log-nats
// logger. Print* counts as Info.
type natsSink struct{ inner mux.LevelLogger }

func (n natsSink) on(l Level) bool { return l >= Level(natsMinLevel.Load()) }

func (n natsSink) Trace(v ...any) {
	if n.on(LTrace) {
		n.inner.Trace(v...)
	}
}
func (n natsSink) Tracef(f string, v ...any) {
	if n.on(LTrace) {
		n.inner.Tracef(f, v...)
	}
}
func (n natsSink) Traceln(v ...any) {
	if n.on(LTrace) {
		n.inner.Traceln(v...)
	}
}
func (n natsSink) Debug(v ...any) {
	if n.on(LDebug) {
		n.inner.Debug(v...)
	}
}
func (n natsSink) Debugf(f string, v ...any) {
	if n.on(LDebug) {
		n.inner.Debugf(f, v...)
	}
}
func (n natsSink) Debugln(v ...any) {
	if n.on(LDebug) {
		n.inner.Debugln(v...)
	}
}
func (n natsSink) Info(v ...any) {
	if n.on(LInfo) {
		n.inner.Info(v...)
	}
}
func (n natsSink) Infof(f string, v ...any) {
	if n.on(LInfo) {
		n.inner.Infof(f, v...)
	}
}
func (n natsSink) Infoln(v ...any) {
	if n.on(LInfo) {
		n.inner.Infoln(v...)
	}
}
func (n natsSink) Notice(v ...any) {
	if n.on(LNotice) {
		n.inner.Notice(v...)
	}
}
func (n natsSink) Noticef(f string, v ...any) {
	if n.on(LNotice) {
		n.inner.Noticef(f, v...)
	}
}
func (n natsSink) Noticeln(v ...any) {
	if n.on(LNotice) {
		n.inner.Noticeln(v...)
	}
}
func (n natsSink) Warn(v ...any) {
	if n.on(LWarn) {
		n.inner.Warn(v...)
	}
}
func (n natsSink) Warnf(f string, v ...any) {
	if n.on(LWarn) {
		n.inner.Warnf(f, v...)
	}
}
func (n natsSink) Warnln(v ...any) {
	if n.on(LWarn) {
		n.inner.Warnln(v...)
	}
}
func (n natsSink) Error(v ...any) {
	if n.on(LError) {
		n.inner.Error(v...)
	}
}
func (n natsSink) Errorf(f string, v ...any) {
	if n.on(LError) {
		n.inner.Errorf(f, v...)
	}
}
func (n natsSink) Errorln(v ...any) {
	if n.on(LError) {
		n.inner.Errorln(v...)
	}
}
func (n natsSink) Panic(v ...any)            { n.inner.Panic(v...) }
func (n natsSink) Panicf(f string, v ...any) { n.inner.Panicf(f, v...) }
func (n natsSink) Panicln(v ...any)          { n.inner.Panicln(v...) }
func (n natsSink) Fatal(v ...any)            { n.inner.Fatal(v...) }
func (n natsSink) Fatalf(f string, v ...any) { n.inner.Fatalf(f, v...) }
func (n natsSink) Fatalln(v ...any)          { n.inner.Fatalln(v...) }
func (n natsSink) Print(v ...any) {
	if n.on(LInfo) {
		n.inner.Print(v...)
	}
}
func (n natsSink) Printf(f string, v ...any) {
	if n.on(LInfo) {
		n.inner.Printf(f, v...)
	}
}
func (n natsSink) Println(v ...any) {
	if n.on(LInfo) {
		n.inner.Println(v...)
	}
}
