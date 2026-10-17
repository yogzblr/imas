package natsbootstrap

// TestBusCAIsIssuingCAOpenBao runs the bus CA step's read against a real
// OpenBao, which the fake in run_test.go only imitates. It needs a server
// it may configure, e.g.
//
//	bao server -dev -dev-root-token-id=root &
//	IMAS_TEST_OPENBAO_ADDR=http://127.0.0.1:8200 IMAS_TEST_OPENBAO_TOKEN=root \
//	  go test ./internal/natsbootstrap -run OpenBao -v
//
// and is skipped otherwise (CI starts one). It mounts PKI engines at fresh
// random paths and removes them when done.

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/openbao"
	"github.com/yogzblr/imas/internal/openbao/openbaotest"
)

// liveOpenBao returns an admin client for the OpenBao the IMAS_TEST_OPENBAO_*
// variables name, with its address and root token, or skips the test.
func liveOpenBao(t *testing.T) (*openbaotest.Admin, string, string) {
	t.Helper()
	addr, root := os.Getenv("IMAS_TEST_OPENBAO_ADDR"), os.Getenv("IMAS_TEST_OPENBAO_TOKEN")
	if addr == "" || root == "" {
		t.Skip("IMAS_TEST_OPENBAO_ADDR and IMAS_TEST_OPENBAO_TOKEN not set; this test needs a real OpenBao")
	}
	return openbaotest.NewAdmin(t, addr, root), addr, root
}

// randomMount mounts a PKI engine at prefix-<random> and removes it when
// the test ends.
func randomMount(t *testing.T, bao *openbaotest.Admin, prefix string) string {
	t.Helper()
	b := make([]byte, 4)
	rand.Read(b)
	mount := prefix + "-" + hex.EncodeToString(b)
	bao.Must(http.MethodPost, "sys/mounts/"+mount, map[string]any{"type": "pki", "config": map[string]any{"max_lease_ttl": "87600h"}})
	t.Cleanup(func() { bao.Delete("sys/mounts/" + mount) })
	return mount
}

// dataField returns the string field of an OpenBao response's data,
// failing the test when it is absent.
func dataField(t *testing.T, raw []byte, field string) string {
	t.Helper()
	var r struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("decoding %s: %v", raw, err)
	}
	s, _ := r.Data[field].(string)
	if s == "" {
		t.Fatalf("no %s in %s", field, raw)
	}
	return s
}

// issue makes the bus's PKI role on mount (as the farmer chart's
// bootstrap writes imas-farmerbus) and issues a certificate from it, as
// internal/certs does for the bus. It returns the leaf and issuing_ca.
func issue(t *testing.T, bao *openbaotest.Admin, mount string) (leaf, issuingCA string) {
	t.Helper()
	bao.Must(http.MethodPost, mount+"/roles/imas-farmerbus", map[string]any{
		"allowed_domains": "bus.imas-dmz.svc.cluster.local", "allow_bare_domains": true,
		"allow_subdomains": false, "allow_localhost": false, "allow_ip_sans": false,
		"server_flag": true, "client_flag": true, "max_ttl": "1h",
	})
	raw := bao.Must(http.MethodPost, mount+"/issue/imas-farmerbus", map[string]any{
		"common_name": "bus.imas-dmz.svc.cluster.local", "alt_names": "bus.imas-dmz.svc.cluster.local",
		"exclude_cn_from_sans": true, "ttl": "10m",
	})
	return dataField(t, raw, "certificate"), dataField(t, raw, "issuing_ca")
}

// readAsStep runs readBusCA as the bootstrap's nats-trust container
// would: an OpenBao client holding a token with no policy at all (the
// path is unauthenticated, so the handoff token needs no grant).
func readAsStep(t *testing.T, bao *openbaotest.Admin, addr, mount string) string {
	t.Helper()
	raw := bao.Must(http.MethodPost, "auth/token/create", map[string]any{
		"no_default_policy": true, "policies": []string{}, "ttl": "5m",
	})
	var r struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(raw, &r); err != nil || r.Auth.ClientToken == "" {
		t.Fatalf("creating a token without policies: %v %s", err, raw)
	}
	t.Setenv("IMAS_TEST_BUSCA_OPENBAO_ADDR", addr)
	t.Setenv("IMAS_TEST_BUSCA_OPENBAO_ALLOW_INSECURE", "true")
	t.Setenv("IMAS_TEST_BUSCA_OPENBAO_TOKEN", r.Auth.ClientToken)
	ob, err := openbao.NewFromEnv(openbao.Env{
		Addr: "IMAS_TEST_BUSCA_OPENBAO_ADDR", Token: "IMAS_TEST_BUSCA_OPENBAO_TOKEN",
		AuthMethod: "IMAS_TEST_BUSCA_OPENBAO_AUTH_METHOD", AllowInsecure: "IMAS_TEST_BUSCA_OPENBAO_ALLOW_INSECURE",
	}, openbao.Errors{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ob.Close)
	got, err := readBusCA(t.Context(), ob, mount)
	if err != nil {
		t.Fatalf("readBusCA: %v", err)
	}
	return got
}

// verifyAsLoader checks leaf against caPEM the way the loader does: the
// PEM is its only root (cmd/farmerbus-loader, IMAS_LOADER_CA_FILE).
func verifyAsLoader(t *testing.T, caPEM, leafPEM string) {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(caPEM)) {
		t.Fatal("the bus CA PEM holds no certificate")
	}
	b, _ := pem.Decode([]byte(leafPEM))
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "bus.imas-dmz.svc.cluster.local"}); err != nil {
		t.Errorf("the bus certificate does not verify against the bus CA ConfigMap's PEM: %v", err)
	}
}

// The PEM the step writes equals, byte for byte, the issuing_ca of a
// certificate the same mount issues to the bus's role: with a root
// issuer, and with an intermediate one (where cert/ca_chain would add the
// root and differ, so cert/ca is the one to read).
func TestBusCAIsIssuingCAOpenBao(t *testing.T) {
	bao, addr, _ := liveOpenBao(t)

	t.Run("root issuer", func(t *testing.T) {
		mount := randomMount(t, bao, "busca-root")
		bao.Must(http.MethodPost, mount+"/root/generate/internal", map[string]any{"common_name": "imas test root CA", "ttl": "87600h"})
		leaf, issuingCA := issue(t, bao, mount)
		got := readAsStep(t, bao, addr, mount)
		if got != issuingCA {
			t.Errorf("cert/ca = %q,\nissuing_ca = %q", got, issuingCA)
		}
		verifyAsLoader(t, got, leaf)
		// What farmerbus itself writes to tls-rootca.pem (internal/certs,
		// <mount>/ca/pem) is the same certificate.
		_, pemRaw := bao.Call("", http.MethodGet, mount+"/ca/pem", nil)
		if strings.TrimSpace(string(pemRaw)) != strings.TrimSpace(got) {
			t.Errorf("ca/pem = %q, cert/ca = %q", pemRaw, got)
		}
	})

	t.Run("intermediate issuer", func(t *testing.T) {
		rootMount := randomMount(t, bao, "busca-root")
		rootPEM := dataField(t, bao.Must(http.MethodPost, rootMount+"/root/generate/internal", map[string]any{"common_name": "imas test root CA", "ttl": "87600h"}), "certificate")
		mount := randomMount(t, bao, "busca-int")
		csr := dataField(t, bao.Must(http.MethodPost, mount+"/intermediate/generate/internal", map[string]any{"common_name": "imas test intermediate CA"}), "csr")
		signed := dataField(t, bao.Must(http.MethodPost, rootMount+"/root/sign-intermediate", map[string]any{"csr": csr, "format": "pem", "ttl": "8760h"}), "certificate")
		// The whole chain, as an operator imports it: the mount then knows
		// the root too, so cert/ca_chain carries both.
		bao.Must(http.MethodPost, mount+"/intermediate/set-signed", map[string]any{"certificate": signed + "\n" + rootPEM})

		leaf, issuingCA := issue(t, bao, mount)
		got := readAsStep(t, bao, addr, mount)
		if got != issuingCA {
			t.Errorf("cert/ca = %q,\nissuing_ca = %q", got, issuingCA)
		}
		if got != signed {
			t.Error("cert/ca is not the intermediate certificate")
		}
		verifyAsLoader(t, got, leaf)
		chain := dataField(t, bao.Must(http.MethodGet, mount+"/cert/ca_chain", nil), "certificate")
		if chain == issuingCA {
			t.Error("cert/ca_chain equals issuing_ca: the intermediate case no longer tells them apart")
		}
	})
}
