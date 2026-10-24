package wincertutil

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

// exitError stands in for *exec.ExitError: winexec.ExitCode only needs
// its ExitCode method.
type exitError int

func (e exitError) ExitCode() int { return int(e) }
func (e exitError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// notFoundOutDE is certutil's not-found answer on a German host: none of
// the English text exists checks for, only the exit code says "absent".
const notFoundOutDE = `My "Eigene Zertifikate"
CertUtil: -store-Befehl ist fehlgeschlagen: 0x80092004 (-2146885628 CRYPT_E_NOT_FOUND)
CertUtil: Das Objekt oder die Eigenschaft wurde nicht gefunden.`

const foundOut = `My "Personal"
================ Certificate 0 ================
Cert Hash(sha1): abc123
CertUtil: -store command completed successfully.`

// hresultExit is how an HRESULT exit code reaches ExitCode on Windows:
// the uint32 code converted to int.
func hresultExit(hr uint32) exitError {
	return exitError(int(hr))
}

// fakeCertutil replaces runCLI for a test and records the verbs called
// ("-store", "-addstore", "-delstore").
type fakeCertutil struct {
	storeOut string
	storeErr error
	calls    []string
}

func (f *fakeCertutil) install(t *testing.T) {
	t.Helper()
	orig := runCLI
	runCLI = func(_ context.Context, exe string, args []string, _ time.Duration) (string, error) {
		if exe != "certutil.exe" || len(args) == 0 {
			t.Fatalf("unexpected command %s %v", exe, args)
		}
		f.calls = append(f.calls, args[0])
		if args[0] == "-store" {
			return f.storeOut, f.storeErr
		}
		return "CertUtil: command completed successfully.", nil
	}
	t.Cleanup(func() { runCLI = orig })
}

func (f *fakeCertutil) called(verb string) bool {
	for _, c := range f.calls {
		if c == verb {
			return true
		}
	}
	return false
}

func parseCert(t *testing.T, method string) Cert {
	t.Helper()
	cooker, err := (Cert{}).Parse("id1", method, map[string]interface{}{
		"name": "mycert", "thumbprint": "ABC123", "path": `C:\certs\my.cer`,
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cooker.(Cert)
}

func TestCertCases(t *testing.T) {
	missing := fakeCertutil{
		storeOut: notFoundOutDE,
		storeErr: ingredients.CommandError("certutil.exe", hresultExit(cryptENotFound), []byte(notFoundOutDE), nil),
	}
	missingEN := fakeCertutil{
		storeOut: "CertUtil: Cannot find object or property.",
		storeErr: ingredients.CommandError("certutil.exe", exitError(5), []byte("CertUtil: Cannot find object or property."), nil),
	}
	exists := fakeCertutil{storeOut: foundOut}
	tests := []struct {
		name    string
		method  string
		fake    fakeCertutil
		apply   bool
		changed bool
		verb    string // the change command expected; "" for none
	}{
		{"present missing test", methodCertPresent, missing, false, true, ""},
		{"present missing apply", methodCertPresent, missing, true, true, "-addstore"},
		{"present missing english text apply", methodCertPresent, missingEN, true, true, "-addstore"},
		{"present exists apply", methodCertPresent, exists, true, false, ""},
		{"absent missing test", methodCertAbsent, missing, false, false, ""},
		{"absent missing apply", methodCertAbsent, missing, true, false, ""},
		{"absent exists test", methodCertAbsent, exists, false, true, ""},
		{"absent exists apply", methodCertAbsent, exists, true, true, "-delstore"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.fake
			f.install(t)
			c := parseCert(t, tt.method)
			var res cook.Result
			var err error
			if tt.apply {
				res, err = c.Apply(context.Background())
			} else {
				res, err = c.Test(context.Background())
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !res.Succeeded || res.Failed || res.Changed != tt.changed {
				t.Errorf("got Succeeded=%v Failed=%v Changed=%v, want true false %v", res.Succeeded, res.Failed, res.Changed, tt.changed)
			}
			for _, verb := range []string{"-addstore", "-delstore"} {
				if f.called(verb) != (verb == tt.verb) {
					t.Errorf("%s called: %v, want %v (calls %v)", verb, f.called(verb), verb == tt.verb, f.calls)
				}
			}
		})
	}
}

func TestStoreFailureIsError(t *testing.T) {
	// E_ACCESSDENIED with output that says nothing about "not found".
	const out = "CertUtil: -store command FAILED: 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED)"
	f := fakeCertutil{
		storeOut: out,
		storeErr: ingredients.CommandError("certutil.exe", hresultExit(0x80070005), []byte(out), nil),
	}
	f.install(t)
	res, err := parseCert(t, methodCertPresent).Apply(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if !res.Failed || res.Changed {
		t.Errorf("got Failed=%v Changed=%v, want true false", res.Failed, res.Changed)
	}
	if f.called("-addstore") {
		t.Errorf("expected no -addstore, got %v", f.calls)
	}
}

func TestParseRequiresName(t *testing.T) {
	_, err := (Cert{}).Parse("id1", methodCertAbsent, map[string]interface{}{"thumbprint": "ABC123"})
	if err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestParseRequiresThumbprint(t *testing.T) {
	_, err := (Cert{}).Parse("id1", methodCertAbsent, map[string]interface{}{"name": "mycert"})
	if err == nil {
		t.Fatal("expected error for missing thumbprint")
	}
}

func TestParsePresentRequiresPath(t *testing.T) {
	_, err := (Cert{}).Parse("id1", methodCertPresent, map[string]interface{}{"name": "mycert", "thumbprint": "ABC123"})
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestParseInvalidMethod(t *testing.T) {
	_, err := (Cert{}).Parse("id1", "bogus", map[string]interface{}{"name": "mycert", "thumbprint": "ABC123"})
	if err != ingredients.ErrInvalidMethod {
		t.Errorf("expected ErrInvalidMethod, got %v", err)
	}
}

func TestStoreDefault(t *testing.T) {
	c := Cert{params: map[string]interface{}{}}
	if got := c.store(); got != "My" {
		t.Errorf("expected default store My, got %q", got)
	}
}

func TestMethods(t *testing.T) {
	name, methods := Cert{}.Methods()
	if name != ingredientName {
		t.Errorf("expected %q, got %q", ingredientName, name)
	}
	if len(methods) != 2 {
		t.Errorf("expected 2 methods, got %d", len(methods))
	}
}
