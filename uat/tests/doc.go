//go:build uat

// Package uattests holds the UAT gate's acceptance scenarios
// (docs/claude-code-parallel-build-plan.md, section 4h): T1 to T6, K1 to
// K4, S1 to S6, C1 to C8, R1 to R6 and X1 to X5 (tier core, the smoke ones
// named TestSmoke) and L1 to L3 (tier resilience). They run against a
// deployed stack, only with the build tag uat, through uat/tests/run.sh.
// The helpers are in uat/tests/harness; README.md describes the inputs.
package uattests
