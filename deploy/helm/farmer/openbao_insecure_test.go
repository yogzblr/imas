package farmerchart

import (
	"strings"
	"testing"
)

// Unit T5 (I2): imas's OpenBao clients refuse an http:// address unless
// <prefix>OPENBAO_ALLOW_INSECURE is true. The chart sets it only with
// openbaoClient.allowInsecure or for the bundled dev-mode OpenBao, and
// refuses to render any other http:// address.

// openbaoClients maps "<kind>/<name>/<container>" to the env of every
// container (init containers included) that has an imas OpenBao client:
// a *_OPENBAO_ADDR variable.
func openbaoClients(docs []obj) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, d := range docs {
		spec, ok := get(d, "spec", "template", "spec").(obj)
		if !ok {
			continue
		}
		for _, list := range []string{"initContainers", "containers"} {
			cs, _ := spec[list].([]any)
			for _, c := range cs {
				co := c.(obj)
				if _, ok := co["env"].([]any); !ok {
					continue
				}
				env := envValues(co)
				for k := range env {
					if strings.HasSuffix(k, "_OPENBAO_ADDR") && !strings.HasPrefix(k, "BAO_") {
						out[d["kind"].(string)+"/"+get(d, "metadata", "name").(string)+"/"+co["name"].(string)] = env
						break
					}
				}
			}
		}
	}
	return out
}

// checkAllowInsecure checks every client's <prefix>ALLOW_INSECURE: "true"
// when want, absent otherwise.
func checkAllowInsecure(t *testing.T, docs []obj, want bool) {
	t.Helper()
	clients := openbaoClients(docs)
	if len(clients) == 0 {
		t.Fatal("no OpenBao client rendered")
	}
	for where, env := range clients {
		for k := range env {
			prefix, ok := strings.CutSuffix(k, "_OPENBAO_ADDR")
			if !ok {
				continue
			}
			v, set := env[prefix+"_OPENBAO_ALLOW_INSECURE"]
			if want && v != "true" {
				t.Errorf("%s: %s_OPENBAO_ALLOW_INSECURE = %q, want \"true\" (address %s)", where, prefix, v, env[k])
			}
			if !want && set {
				t.Errorf("%s: %s_OPENBAO_ALLOW_INSECURE is set (%q) for address %s", where, prefix, v, env[k])
			}
		}
	}
}

func TestOpenBaoAllowInsecure(t *testing.T) {
	// The eval install: the bundled dev-mode OpenBao, http only.
	dev := mustRender(t)
	checkAllowInsecure(t, dev, true)
	if n := notes(t, mustRenderRelease(t, "")); !strings.Contains(n, "OPENBAO OVER PLAIN HTTP") || !strings.Contains(n, "bundled dev-mode OpenBao") {
		t.Errorf("NOTES does not warn about the dev-mode OpenBao's plain http:\n%s", n)
	}
	// The bootstrap Job's nats-trust step is one of the clients.
	if _, ok := openbaoClients(dev)["Job/t-farmer-openbao-bootstrap/nats-trust"]; !ok {
		t.Errorf("nats-trust not found among the OpenBao clients: %v", keys(openbaoClients(dev)))
	}

	// An external https OpenBao: no client may accept http.
	ext := mustRender(t, "-f", ciValues(t, "external-values.yaml"))
	checkAllowInsecure(t, ext, false)
	if n := notes(t, mustRenderRelease(t, "", "-f", ciValues(t, "external-values.yaml"))); strings.Contains(n, "OPENBAO OVER PLAIN HTTP") {
		t.Errorf("NOTES warns about plain http for an https OpenBao:\n%s", n)
	}

	// The bundled OpenBao out of dev mode (as the UAT runs it): http, so
	// it needs the explicit value.
	mustFail(t, "openbaoClient.allowInsecure=true", "--set", "openbao.server.dev.enabled=false", "--set", "openbaoBootstrap.tokenSecretName=bao-root")
	nonDev := mustRender(t, "--set", "openbao.server.dev.enabled=false", "--set", "openbaoBootstrap.tokenSecretName=bao-root", "--set", "openbaoClient.allowInsecure=true")
	checkAllowInsecure(t, nonDev, true)
	if n := notes(t, mustRenderRelease(t, "", "--set", "openbao.server.dev.enabled=false", "--set", "openbaoBootstrap.tokenSecretName=bao-root", "--set", "openbaoClient.allowInsecure=true")); !strings.Contains(n, "openbaoClient.allowInsecure=true") {
		t.Errorf("NOTES does not name openbaoClient.allowInsecure:\n%s", n)
	}

	// An external http address renders only with allowInsecure.
	httpAddr := []string{"-f", ciValues(t, "external-values.yaml"), "--set", "openbaoClient.addr=http://openbao.openbao.svc:8200"}
	mustFail(t, "openbaoClient.allowInsecure=true", httpAddr...)
	checkAllowInsecure(t, mustRender(t, append(httpAddr, "--set", "openbaoClient.allowInsecure=true")...), true)

	// Neither scheme-less nor unix addresses render.
	mustFail(t, "must be an https:// URL", "-f", ciValues(t, "external-values.yaml"), "--set", "openbaoClient.addr=openbao.openbao.svc:8200")
	mustFail(t, "must be an https:// URL", "-f", ciValues(t, "external-values.yaml"), "--set", "openbaoClient.addr=unix:///run/bao.sock")
}

func keys(m map[string]map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
