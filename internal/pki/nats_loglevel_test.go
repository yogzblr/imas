package pki

import (
	"testing"

	"github.com/yogzblr/imas/internal/config"
)

// The bus options never turn on nats-server's debug or trace log, whose
// trace level carries every payload (security review 2026-10, L13);
// cmd/farmerbus raises them only for IMAS_BUS_LOG_LEVEL=trace or debug.
func TestBaseNatsOptionsNoTraceOrDebug(t *testing.T) {
	setupTestPKI(t)
	config.FarmerBusPort = "-1"
	opts := baseNatsOptions()
	if opts.Trace || opts.Debug || opts.TraceVerbose {
		t.Fatalf("Trace %t, Debug %t, TraceVerbose %t; want all off", opts.Trace, opts.Debug, opts.TraceVerbose)
	}
}
