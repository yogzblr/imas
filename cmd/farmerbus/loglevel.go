package main

// The bus's own nats-server log level (security review 2026-10, L13).
// FLAG FOR SECURITY REVIEW.
//
// nats-server's debug log names every connection and subscription, and
// its trace log carries every protocol line, payloads included: CLI
// tokens, shell keystrokes, internal.* bodies and every unsealed payload,
// for every tenant. So neither is on unless IMAS_BUS_LOG_LEVEL asks for
// it. farmer's "loglevel" (config.LogLevel) does not turn them on: it
// only filters what reaches the terminal logger.

import (
	"fmt"
	"strings"

	nats_server "github.com/nats-io/nats-server/v2/server"

	log "github.com/yogzblr/imas/internal/log"
)

// envBusLogLevel is the bus's nats-server log level: info (the default
// when unset), debug or trace.
const envBusLogLevel = "IMAS_BUS_LOG_LEVEL"

// busLogLevel is how much nats-server itself logs.
type busLogLevel int

const (
	// busLogInfo: notices, warnings and errors only. No debug, no trace.
	busLogInfo busLogLevel = iota
	// busLogDebug adds nats-server's debug lines (connections,
	// subscriptions, account updates), never a payload.
	busLogDebug
	// busLogTrace adds every protocol line, payloads included.
	busLogTrace
)

func (l busLogLevel) String() string {
	switch l {
	case busLogDebug:
		return "debug"
	case busLogTrace:
		return "trace"
	default:
		return "info"
	}
}

// parseBusLogLevel reads IMAS_BUS_LOG_LEVEL's value. Empty is info;
// anything other than info, debug or trace is an error, so a typo never
// turns trace on or off silently.
func parseBusLogLevel(v string) (busLogLevel, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "info":
		return busLogInfo, nil
	case "debug":
		return busLogDebug, nil
	case "trace":
		return busLogTrace, nil
	}
	return busLogInfo, fmt.Errorf("%s=%q: want info, debug or trace", envBusLogLevel, v)
}

// apply sets nats-server's Debug and Trace options for l.
func (l busLogLevel) apply(opts *nats_server.Options) {
	opts.Debug = l >= busLogDebug
	opts.Trace = l >= busLogTrace
}

// terminalLevel is the terminal logger's level that lets l's lines
// through: nats-server's debug and trace lines reach it as Debugf and
// Tracef, which a farmer "loglevel" of info would drop. It never lowers
// a level that is already more verbose.
func (l busLogLevel) terminalLevel(cur log.Level) log.Level {
	switch {
	case l == busLogTrace && cur > log.LTrace:
		return log.LTrace
	case l == busLogDebug && cur > log.LDebug:
		return log.LDebug
	}
	return cur
}
