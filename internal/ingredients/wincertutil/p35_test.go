package wincertutil

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/ingredients"
)

// foundNoKeyOut is certutil -store's answer, exit 0, for the UAT cases'
// throwaway certificate, whose private key was discarded: a match that
// also says "Cannot find the certificate and private key for decryption."
const foundNoKeyOut = `My "Personal"
================ Certificate 0 ================
Serial Number: 02b747ef3871d6c1f1b8de701a782312ac9b2944
Issuer: CN=imas-uat-throwaway-test-cert
 NotBefore: 10/6/2026 5:48 PM
 NotAfter: 9/12/2126 5:48 PM
Subject: CN=imas-uat-throwaway-test-cert
Signature matches Public Key
Root Certificate: Subject matches Issuer
Cert Hash(sha1): 3d0aa4d63a52b151d025d38a267b37ddbce45d8e
No key provider information
Cannot find the certificate and private key for decryption.
CertUtil: -store command completed successfully.`

// UAT I.win_certutil.cert_present / cert_absent, Run 2 on rc.21: the
// second real cook of cert_present reported "imas-uat has been added"
// again, and cert_absent left the certificate in the store. A match
// whose output mentions the missing private key is still a match.
func TestCertWithoutPrivateKeyIsPresent(t *testing.T) {
	f := fakeCertutil{storeOut: foundNoKeyOut}
	f.install(t)
	res, err := parseCert(t, methodCertPresent).Apply(context.Background())
	if err != nil || !res.Succeeded || res.Changed || f.called("-addstore") {
		t.Fatalf("cert_present on a stored cert: res=%+v err=%v calls=%v", res, err, f.calls)
	}
	res, err = parseCert(t, methodCertAbsent).Apply(context.Background())
	if err != nil || !res.Changed || !f.called("-delstore") {
		t.Fatalf("cert_absent on a stored cert: res=%+v err=%v calls=%v", res, err, f.calls)
	}
}

func TestCertIDIsNormalised(t *testing.T) {
	var args []string
	orig := runCLI
	runCLI = func(_ context.Context, _ string, a []string, _ time.Duration) (string, error) {
		args = a
		return foundOut, nil
	}
	t.Cleanup(func() { runCLI = orig })
	c, err := (Cert{}).Parse("id1", methodCertAbsent, map[string]interface{}{
		"name": "x", "thumbprint": " 3d 0a a4 d6 3a 52 b1 51 d0 25 d3 8a 26 7b 37 dd bc e4 5d 8e ",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Test(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(args) != 3 || args[0] != "-store" || args[1] != "My" || args[2] != "3D0AA4D63A52B151D025D38A267B37DDBCE45D8E" {
		t.Errorf("certutil args = %q", args)
	}
}

// An exit that is not CRYPT_E_NOT_FOUND, with output that merely
// contains "not found", is an error that names the store, not "absent".
func TestOtherFailureIsNotAbsent(t *testing.T) {
	const out = "CertUtil: -store command FAILED: 0x80090016 (-2146893802 NTE_BAD_KEYSET)\nCertUtil: Keyset does not exist; provider not found"
	f := fakeCertutil{storeOut: out, storeErr: ingredients.CommandError("certutil.exe", hresultExit(0x80090016), []byte(out), nil)}
	f.install(t)
	_, err := parseCert(t, methodCertAbsent).Test(context.Background())
	if err == nil || !strings.Contains(err.Error(), "store My") || !strings.Contains(err.Error(), "NTE_BAD_KEYSET") {
		t.Fatalf("err = %v", err)
	}
}
