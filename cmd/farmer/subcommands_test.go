package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
	"github.com/yogzblr/imas/internal/sproutrelease"
)

// The pre-config subcommands are dispatched, by the names the chart's
// hook Jobs run, before anything loads farmer's config; anything else
// falls through to the server.
func TestRunPreConfigSubcommandDispatch(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"--help-me"}, {"serve"}, {"publish-saasapi-credential"}} {
		if _, ok := runPreConfigSubcommand(args, &bytes.Buffer{}, &bytes.Buffer{}); ok {
			t.Errorf("%v was taken as a pre-config subcommand", args)
		}
	}
	// The names the chart runs (chart_test.go checks the Jobs' args).
	if pki.ControlPlaneBoxKeysCommand != "ensure-controlplane-box-keys" || sproutrelease.Command != "register-sprout-release" {
		t.Fatalf("subcommand names changed: %q %q", pki.ControlPlaneBoxKeysCommand, sproutrelease.Command)
	}
	var stderr bytes.Buffer
	code, ok := runPreConfigSubcommand([]string{sproutrelease.Command, "-no-such-flag"}, &bytes.Buffer{}, &stderr)
	if !ok || code != 2 {
		t.Errorf("register-sprout-release with a bad flag: ok=%v code=%d %s", ok, code, stderr.String())
	}
}

// ensure-controlplane-box-keys runs the keygen, not the server: without
// its OpenBao identity it is a usage error, and with one it creates the
// keys, without loading farmer's config.
func TestRunPreConfigSubcommandControlPlaneBoxKeys(t *testing.T) {
	before := config.FarmerOrganization
	t.Setenv(pki.EnvCPBoxOpenBaoAddr, "")
	var stderr bytes.Buffer
	code, ok := runPreConfigSubcommand([]string{pki.ControlPlaneBoxKeysCommand}, &bytes.Buffer{}, &stderr)
	if !ok || code != 2 {
		t.Fatalf("unconfigured: ok=%v code=%d %s", ok, code, stderr.String())
	}

	srv := tenantboxtest.Start(t)
	t.Setenv(pki.EnvCPBoxOpenBaoAddr, srv.URL)
	t.Setenv(pki.EnvCPBoxOpenBaoAuthMethod, "token")
	t.Setenv(pki.EnvCPBoxOpenBaoToken, tenantboxtest.Token)
	t.Setenv(pki.EnvCPBoxOpenBaoKVPath, tenantboxtest.BasePath)
	stderr.Reset()
	code, ok = runPreConfigSubcommand([]string{pki.ControlPlaneBoxKeysCommand}, &bytes.Buffer{}, &stderr)
	if !ok || code != 0 {
		t.Fatalf("configured: ok=%v code=%d %s", ok, code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "platform key created") {
		t.Errorf("output %q", stderr.String())
	}
	if len(srv.Versions(tenantboxtest.BasePath+"/platform")) != 1 || len(srv.Versions(tenantboxtest.BasePath+"/controlplane-pub")) != 1 {
		t.Error("keys not written")
	}
	if config.FarmerOrganization != before {
		t.Error("the subcommand loaded farmer's config")
	}
}
