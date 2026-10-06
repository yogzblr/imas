// Command fakestack serves the in-memory fake of the UAT stack
// (uat/tests/harness/fakestack) and writes a material directory and a
// vmctl.sh for it, so uat/tests/run.sh can be exercised end to end
// without a deployment:
//
//	go run ./uat/tests/fakestack -dir /tmp/uat-fake &
//	IMAS_UAT_DIR=/tmp/uat-fake uat/tests/run.sh smoke
//
// The fake implements what the smoke tier and the harness's own tests
// need, nothing more. A green run against it proves the suite's plumbing
// (material loading, tokens, batches, vmctl.sh, the report and the no
// silent green rule), never the product. The vmctl.sh it writes needs
// curl.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/yogzblr/imas/uat/tests/harness/fakestack"
)

const vmctlScript = `#!/usr/bin/env bash
# vmctl.sh for the fake stack: forwards to its /_vmctl endpoint.
set -euo pipefail
verb=$2
vm=$3
script=${4:-}
out=$(mktemp)
trap 'rm -f "$out"' EXIT
code=$(printf '%%s' "$script" | curl -sS --cacert %q -o "$out" -D - --data-binary @- \
	"%s/_vmctl?verb=$verb&vm=$vm" | tr -d '\r' | sed -n 's/^[Xx]-[Ee]xit-[Cc]ode: //p')
cat "$out"
exit "${code:-1}"
`

func main() {
	dir := flag.String("dir", "", "directory to write the material into (created if missing)")
	layout := flag.String("layout", "flat", "flat (keycloak.json and friends) or core (uat/hub/core's core.json and credentials.json)")
	flag.Parse()
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "usage: fakestack -dir DIR")
		os.Exit(2)
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	s := fakestack.New()
	defer s.Close()
	s.AddContractHosts()
	vmctl := filepath.Join(abs, "vmctl.sh")
	ca := filepath.Join(abs, "uat-ca.pem")
	if *layout == "core" {
		ca = filepath.Join(abs, "core", "out", "uat-ca.crt")
	}
	script := fmt.Sprintf(vmctlScript, ca, s.Server.URL)
	if err := os.WriteFile(vmctl, []byte(script), 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	write := s.WriteMaterial
	if *layout == "core" {
		write = s.WriteCoreMaterial
	}
	if err := write(abs, vmctl); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// .ready tells a waiting test every file is written.
	if err := os.WriteFile(filepath.Join(abs, ".ready"), nil, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("fake UAT stack at %s\nexport IMAS_UAT_DIR=%s IMAS_UAT_VMCTL=%s\n", s.Server.URL, abs, vmctl)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
