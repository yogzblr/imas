package saasapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// LoadConfig reads saasapi's Valkey addresses, password file and TLS
// settings, and refuses a password file that is missing or empty and TLS
// without a usable CA.
func TestLoadConfigValkey(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pw := write("password", "rate-limit-pw\n")
	empty := write("empty", "")
	notPEM := write("ca.crt", "not a certificate")

	for _, k := range []string{"SAASAPI_VALKEY_ADDRS", "SAASAPI_VALKEY_PASSWORD_FILE", "SAASAPI_VALKEY_TLS",
		"SAASAPI_VALKEY_TLS_CA_FILE", "SAASAPI_VALKEY_TLS_SERVER_NAME"} {
		t.Setenv(k, "")
	}

	t.Run("unset", func(t *testing.T) {
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.ValkeyAddrs) != 0 || cfg.Valkey.Password != "" || cfg.Valkey.TLS != nil {
			t.Errorf("ValkeyAddrs %v, Valkey %v", cfg.ValkeyAddrs, cfg.Valkey)
		}
	})
	t.Run("password", func(t *testing.T) {
		t.Setenv("SAASAPI_VALKEY_ADDRS", "valkey-0:6379, valkey-1:6379")
		t.Setenv("SAASAPI_VALKEY_PASSWORD_FILE", pw)
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.ValkeyAddrs) != 2 || cfg.Valkey.Password != "rate-limit-pw" {
			t.Errorf("ValkeyAddrs %v, password %q", cfg.ValkeyAddrs, cfg.Valkey.Password)
		}
	})
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"missing password file", map[string]string{"SAASAPI_VALKEY_PASSWORD_FILE": filepath.Join(dir, "nope")}, "SAASAPI_VALKEY_PASSWORD_FILE"},
		{"empty password file", map[string]string{"SAASAPI_VALKEY_PASSWORD_FILE": empty}, "empty"},
		{"TLS without a CA", map[string]string{"SAASAPI_VALKEY_TLS": "true"}, "SAASAPI_VALKEY_TLS_CA_FILE"},
		{"bad PEM", map[string]string{"SAASAPI_VALKEY_TLS": "true", "SAASAPI_VALKEY_TLS_CA_FILE": notPEM}, "no PEM certificate"},
		{"TLS not a boolean", map[string]string{"SAASAPI_VALKEY_TLS": "on-ish"}, "SAASAPI_VALKEY_TLS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one naming %q", err, tc.want)
			}
		})
	}
}
