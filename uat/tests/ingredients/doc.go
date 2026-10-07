// Package ingredients is the UAT gate's ingredient conformance suite
// (docs/claude-code-parallel-build-plan.md, section 4h, UAT.7) and its
// lifecycle scenarios L4 and L5.
//
// Without a build tag it holds what can be checked anywhere, and is unit
// tested by go test ./...:
//
//   - the registry (registry.go, eval.go): every ingredient method a sprout
//     registers on Linux and on Windows, read from the source of
//     cmd/sprout's imports for each GOOS, with its properties;
//     uat/cases/INVENTORY.md is generated from it (inventory.go);
//   - the case files of uat/cases (cases.go; the format is
//     uat/cases/README.md) and the coverage rule (coverage.go): every
//     registered method on every OS has a case or a written skip, so a new
//     ingredient can't slip in untested;
//   - the cycle a case runs on one sprout (cycle.go): test mode, a real
//     cook, test mode again, a second real cook, the out of band check and
//     the revert, written against a Driver so it is tested with a fake
//     sprout;
//   - the -test.run selection the runner applies to its own work (match.go).
//
// With the build tag uat (go test -tags uat, through uat/tests/run.sh) it
// adds TestIngredients, TestIngredientsCoverage and TestLifecycle against a
// deployed stack, on top of uat/tests/harness.
package ingredients
