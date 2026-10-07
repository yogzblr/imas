package farmerchart

import (
	"bytes"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// busHost points farmer and saasapi at a bus outside this cluster, the
// way the UAT core hub reaches the DMZ (owner decision 2026-10-06:
// dmz.uat.imas.internal, node port 8442), with no bus Service values.
var busHost = []string{
	"--set", "bus.host=dmz.uat.imas.internal",
	"--set", "bus.port=8442",
	"--set", "bus.serviceName=",
	"--set", "bus.namespace=",
}

// rawTemplate is `helm template` of the stripped chart as text, for
// byte-level checks the parsed YAML can't make.
func rawTemplate(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(helmBin(t), append([]string{"template", "t", strippedChart(t),
		"--namespace", "imas-core", "--kube-version", "1.30.0"}, append(slices.Clone(required), args...)...)...)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("helm template failed: %s", stderr.String())
	}
	return out.String()
}

// busURLs returns farmer's farmerbusurl and saasapi's SAASAPI_NATS_URL.
func busURLs(t *testing.T, docs []obj) (farmer, saasapi string) {
	t.Helper()
	farmer, _ = farmerConfig(t, docs)["farmerbusurl"].(string)
	saasapi = envValues(container(t, find(t, docs, "Deployment", "t-farmer-saasapi"), "saasapi"))["SAASAPI_NATS_URL"]
	return farmer, saasapi
}

// busEgressRule is the first egress rule of a NetworkPolicy: the bus.
func busEgressRule(t *testing.T, docs []obj, name string) obj {
	t.Helper()
	r, _ := get(find(t, docs, "NetworkPolicy", name), "spec", "egress", 0).(obj)
	return r
}

func selectorBusRule(port int) obj {
	return obj{
		"to": []any{obj{
			"namespaceSelector": obj{"matchLabels": obj{"kubernetes.io/metadata.name": "imas-dmz"}},
			"podSelector":       obj{"matchLabels": obj{"app.kubernetes.io/name": "nats", "app.kubernetes.io/component": "bus"}},
		}},
		"ports": []any{obj{"protocol": "TCP", "port": port}},
	}
}

// The text of the bus egress rule as main rendered it before bus.host,
// indented as it sits under each NetworkPolicy's egress.
const defaultBusEgress = `  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: imas-dmz
          podSelector:
            matchLabels:
              app.kubernetes.io/component: bus
              app.kubernetes.io/name: nats
      ports:
        - { protocol: TCP, port: 5406 }
`

// Without bus.host nothing changes: for every ci values file, both URLs
// are the bus Service FQDN, both bus egress rules are the selector rule,
// byte for byte (no ipBlock peer), and NOTES names the FQDN as the SAN.
// (The PR checked the full `helm template` output of each ci file against
// main; this pins the parts bus.host touches.)
func TestBusHostUnsetUnchanged(t *testing.T) {
	const url = "tls://imas-dmz-nats-bus.imas-dmz.svc.cluster.local:5406"
	for _, f := range []string{"default-values.yaml", "external-values.yaml", "token-auth-values.yaml"} {
		t.Run(f, func(t *testing.T) {
			args := []string{"-f", ciValues(t, f)}
			docs := mustRender(t, args...)
			if fu, su := busURLs(t, docs); fu != url || su != url {
				t.Errorf("farmerbusurl %q, SAASAPI_NATS_URL %q, want %s", fu, su, url)
			}
			for _, np := range []string{"t-farmer", "t-farmer-saasapi"} {
				if got := busEgressRule(t, docs, np); !reflect.DeepEqual(got, selectorBusRule(5406)) {
					t.Errorf("%s bus egress %v", np, got)
				}
			}
			raw := rawTemplate(t, append(args, "--show-only", "templates/networkpolicy.yaml")...)
			if n := strings.Count(raw, defaultBusEgress); n != 2 {
				t.Errorf("the default bus egress rule appears %d times, want 2 (farmer, saasapi):\n%s", n, raw)
			}
			saasapi := rawTemplate(t, append(args, "--show-only", "templates/saasapi-deployment.yaml")...)
			if !strings.Contains(saasapi, "            # The same URL as farmer's farmerbusurl. saasapi verifies the\n"+
				"            # bus certificate against its host, the Service FQDN (a SAN on\n"+
				"            # the nats chart's default bus certificate).\n"+
				"            - name: SAASAPI_NATS_URL\n") {
				t.Errorf("saasapi's SAASAPI_NATS_URL comment changed:\n%s", saasapi)
			}
			n := notes(t, mustRenderRelease(t, "", args...))
			if want := "farmer (farmerbusurl) and saasapi dial the bus at " + url + ";\n" +
				"the bus certificate must carry imas-dmz-nats-bus.imas-dmz.svc.cluster.local as a SAN.\n\n"; !strings.Contains(n, want) {
				t.Errorf("NOTES lack %q:\n%s", want, n)
			}
			if strings.Contains(n, "bus.host") {
				t.Errorf("NOTES mention bus.host without it:\n%s", n)
			}
		})
	}
}

// bus.host replaces the Service FQDN in both URLs, so neither
// bus.serviceName nor bus.namespace is needed, and the name farmer
// verifies follows it unless bus.tlsServerName says otherwise.
func TestBusHostURLs(t *testing.T) {
	const url = "tls://dmz.uat.imas.internal:8442"
	docs := mustRender(t, busHost...)
	if fu, su := busURLs(t, docs); fu != url || su != url {
		t.Errorf("farmerbusurl %q, SAASAPI_NATS_URL %q, want %s", fu, su, url)
	}
	cfg := farmerConfig(t, docs)
	if cfg["farmerbusport"] != "8442" {
		t.Errorf("farmerbusport = %v", cfg["farmerbusport"])
	}
	if _, ok := cfg["farmerbustlsservername"]; ok {
		t.Error("farmerbustlsservername set; with bus.host it should follow farmerbusurl's host")
	}

	n := notes(t, mustRenderRelease(t, "", busHost...))
	for _, want := range []string{
		"dial the bus at " + url + ";",
		"the bus certificate must carry dmz.uat.imas.internal as a SAN (bus.host: saasapi verifies the name it dials).",
		"WARNING: bus.host is set but bus.egressCIDRs is empty.",
	} {
		if !strings.Contains(n, want) {
			t.Errorf("NOTES lack %q:\n%s", want, n)
		}
	}
	n = notes(t, mustRenderRelease(t, "", append(slices.Clone(busHost), "--set", "bus.tlsServerName=bus.dmz.example",
		"--set", "bus.egressCIDRs[0]=10.20.1.4/32")...))
	if want := "carry dmz.uat.imas.internal as a SAN (bus.host: saasapi verifies the name it dials), and bus.dmz.example (bus.tlsServerName, the name farmer verifies)."; !strings.Contains(n, want) {
		t.Errorf("NOTES lack %q:\n%s", want, n)
	}
	if strings.Contains(n, "WARNING: bus.host") {
		t.Errorf("NOTES warn about bus.egressCIDRs that is set:\n%s", n)
	}
	if n := notes(t, mustRenderRelease(t, "", append(slices.Clone(busHost), "--set", "networkPolicy.enabled=false")...)); strings.Contains(n, "WARNING: bus.host") {
		t.Errorf("NOTES warn about egress with networkPolicy.enabled=false:\n%s", n)
	}

	// A farmerbus PKI role can't default to the in-cluster Service names
	// when the bus is dialed at bus.host.
	farmerbus := append(slices.Clone(busHost), "--set", "openbaoBootstrap.farmerbus.enabled=true",
		"--set", "openbaoBootstrap.farmerbus.serviceAccountName=imas-dmz-nats-bus")
	mustFail(t, "openbaoBootstrap.farmerbus.allowedNames is required with bus.host", farmerbus...)
	mustFail(t, "bus.namespace is required with openbaoBootstrap.farmerbus.enabled",
		append(slices.Clone(farmerbus), "--set", "openbaoBootstrap.farmerbus.allowedNames[0]=dmz.uat.imas.internal")...)
	docs = mustRender(t, append(slices.Clone(farmerbus), "--set", "openbaoBootstrap.farmerbus.allowedNames[0]=dmz.uat.imas.internal",
		"--set", "bus.namespace=imas-dmz")...)
	script := get(container(t, find(t, docs, "Job", "t-farmer-openbao-bootstrap"), "bootstrap"), "args", 0).(string)
	if !strings.Contains(script, `allowed_domains="dmz.uat.imas.internal"`) {
		t.Errorf("imas-farmerbus role doesn't allow bus.host:\n%s", script)
	}
}

// bus.host is a bare DNS name, like bus.tlsServerName; a URL or host:port
// would build a broken farmerbusurl, and an IP address is refused too.
// bus.egressCIDRs entries are CIDRs.
func TestBusHostValidation(t *testing.T) {
	for _, bad := range []string{
		"tls://dmz.uat.imas.internal:8442",
		"tls://dmz.uat.imas.internal",
		"dmz.uat.imas.internal:8442",
		"dmz.uat.imas.internal/",
		"-dmz.uat.imas.internal",
		"dmz.uat.imas.internal.",
		"dmz uat",
	} {
		t.Run(bad, func(t *testing.T) {
			mustFail(t, "must be a bare DNS name", append(slices.Clone(busHost), "--set-string", "bus.host="+bad)...)
		})
	}
	// No IP addresses (owner decision 2026-10-06): the bus certificate
	// carries bus.host as a DNS SAN, and addresses go in bus.egressCIDRs.
	for _, ip := range []string{
		"10.20.1.4",
		"10.20.1.4:8442",
		"127.1",
		"fd00:20::4",
		"::1",
		"[fd00:20::4]",
		"[fd00:20::4]:8442",
		"::ffff:10.20.1.4",
	} {
		t.Run("ip "+ip, func(t *testing.T) {
			mustFail(t, "is an IP address", append(slices.Clone(busHost), "--set-string", "bus.host="+ip)...)
		})
	}
	// Names that merely contain digits are still DNS names.
	for _, ok := range []string{"10-20-1-4.dmz.uat.imas.internal", "dmz1.uat.imas.internal", "a1b2"} {
		if _, err := render(t, append(slices.Clone(busHost), "--set-string", "bus.host="+ok)...); err != nil {
			t.Errorf("bus.host=%s refused: %v", ok, err)
		}
	}
	// Without bus.host the bus Service values stay required.
	mustFail(t, "bus.serviceName is required", "--set", "bus.serviceName=")
	mustFail(t, "bus.namespace is required", "--set", "bus.namespace=")

	for _, bad := range []string{"10.20.1.4", "dmz.uat.imas.internal", "10.20.1.4/32 ", "10.20.1/24"} {
		t.Run("cidr "+bad, func(t *testing.T) {
			mustFail(t, "must be a CIDR", append(slices.Clone(busHost), "--set-string", "bus.egressCIDRs[0]="+bad)...)
		})
	}
	mustFail(t, "bus.egressCIDRs must be a list", append(slices.Clone(busHost), "--set-string", "bus.egressCIDRs=10.20.1.4/32")...)
}

// A selector can't match a bus outside the cluster: with bus.host and
// bus.egressCIDRs, farmer's and saasapi's bus egress rules are exactly an
// ipBlock per CIDR on bus.port. With bus.host alone the selector rule
// stays (never "any destination"); without bus.host the CIDRs are added
// next to the selector.
func TestBusEgressIPBlock(t *testing.T) {
	ipBlocks := []any{
		obj{"ipBlock": obj{"cidr": "10.20.1.4/32"}},
		obj{"ipBlock": obj{"cidr": "fd00:20::/64"}},
	}
	cidrs := []string{"--set", "bus.egressCIDRs[0]=10.20.1.4/32", "--set", "bus.egressCIDRs[1]=fd00:20::/64"}

	docs := mustRender(t, append(slices.Clone(busHost), cidrs...)...)
	want := obj{"to": ipBlocks, "ports": []any{obj{"protocol": "TCP", "port": 8442}}}
	for _, np := range []string{"t-farmer", "t-farmer-saasapi"} {
		if got := busEgressRule(t, docs, np); !reflect.DeepEqual(got, want) {
			t.Errorf("%s bus egress %v, want %v", np, got, want)
		}
		// The in-cluster bus pods are no longer admitted.
		if allows(find(t, docs, "NetworkPolicy", np), "egress", "imas-dmz", obj{"app.kubernetes.io/name": "nats", "app.kubernetes.io/component": "bus"}, 8442) {
			t.Errorf("%s still admits the in-cluster bus pods", np)
		}
	}

	docs = mustRender(t, busHost...)
	for _, np := range []string{"t-farmer", "t-farmer-saasapi"} {
		if got := busEgressRule(t, docs, np); !reflect.DeepEqual(got, selectorBusRule(8442)) {
			t.Errorf("%s bus egress without bus.egressCIDRs %v, want the selector rule", np, got)
		}
	}

	docs = mustRender(t, cidrs...)
	want = selectorBusRule(5406)
	want["to"] = append(want["to"].([]any), ipBlocks...)
	for _, np := range []string{"t-farmer", "t-farmer-saasapi"} {
		if got := busEgressRule(t, docs, np); !reflect.DeepEqual(got, want) {
			t.Errorf("%s bus egress %v, want %v", np, got, want)
		}
	}
}
