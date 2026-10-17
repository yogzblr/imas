package natschart

import "testing"

// Unit T5 (I2): the bus's OpenBao client refuses an http:// address
// unless IMAS_CERTS_OPENBAO_ALLOW_INSECURE is true, which the chart sets
// only with bus.tls.openbao.allowInsecure, and an http:// address
// without it does not render.
func TestOpenBaoTLSModeAllowInsecure(t *testing.T) {
	env := envMap(container(t, find(t, mustRender(t, "--set", "bus.tls.mode=openbao"), "StatefulSet", "-bus")))
	if _, set := env["IMAS_CERTS_OPENBAO_ALLOW_INSECURE"]; set {
		t.Errorf("IMAS_CERTS_OPENBAO_ALLOW_INSECURE set for %s", env["IMAS_CERTS_OPENBAO_ADDR"])
	}

	httpAddr := []string{"--set", "bus.tls.mode=openbao", "--set", "bus.tls.openbao.addr=http://openbao.openbao.svc:8200"}
	mustFail(t, "bus.tls.openbao.allowInsecure=true", httpAddr...)
	env = envMap(container(t, find(t, mustRender(t, append(httpAddr, "--set", "bus.tls.openbao.allowInsecure=true")...), "StatefulSet", "-bus")))
	if env["IMAS_CERTS_OPENBAO_ALLOW_INSECURE"] != "true" {
		t.Errorf("IMAS_CERTS_OPENBAO_ALLOW_INSECURE = %q with bus.tls.openbao.allowInsecure=true", env["IMAS_CERTS_OPENBAO_ALLOW_INSECURE"])
	}

	mustFail(t, "must be an https:// URL", "--set", "bus.tls.mode=openbao", "--set", "bus.tls.openbao.addr=openbao.openbao.svc:8200")
	// Secret mode ignores the OpenBao settings, http or not.
	mustRender(t, "--set", "bus.tls.openbao.addr=http://openbao.openbao.svc:8200")
}
