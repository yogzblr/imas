package mysqldsn

import (
	"strings"
	"testing"
)

func TestRequireUTC(t *testing.T) {
	const secret = "s3cr3t-pw"
	for dsn, ok := range map[string]bool{
		"u:" + secret + "@tcp(pxc:3306)/farmer":                                        true,
		"u:" + secret + "@tcp(pxc:3306)/farmer?parseTime=true":                         true,
		"u:" + secret + "@tcp(pxc:3306)/farmer?parseTime=true&loc=UTC":                 true,
		"u:" + secret + "@tcp(pxc:3306)/farmer?parseTime=true&charset=utf8mb4&loc=UTC": true,
		"u:" + secret + "@tcp(pxc:3306)/farmer?parseTime=true&loc=Local":               false,
		"u:" + secret + "@tcp(pxc:3306)/farmer?parseTime=true&loc=Europe%2FLondon":     false,
		"u:" + secret + "@tcp(pxc:3306)/farmer?loc=Asia%2FKolkata&parseTime=true":      false,
		"u:" + secret + "@tcp(pxc:3306)farmer":                                         false, // not a DSN
	} {
		err := RequireUTC("IMAS_PXC_DSN", dsn)
		if ok && err != nil {
			t.Errorf("RequireUTC(%q) = %v", dsn, err)
		}
		if !ok && err == nil {
			t.Errorf("RequireUTC(%q) accepted it", dsn)
		}
		if err != nil {
			if !strings.Contains(err.Error(), "IMAS_PXC_DSN") {
				t.Errorf("error %q does not name the setting", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error %q carries the password", err)
			}
		}
	}
	if err := RequireUTC("S", "u:p@tcp(h:1)/d?loc=Local"); err == nil || !strings.Contains(err.Error(), "loc=UTC") {
		t.Errorf("a non-UTC loc: %v, want an error naming loc=UTC", err)
	}
}
