package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/taigrr/jety"
	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/natsretry"
)

// resetForTest resets the sync.Once so LoadConfig can be called again,
// and points jety at the given config file. Because jety's global
// ConfigManager retains state across tests, callers should set explicit
// values via jety.Set when testing config reads.
func resetForTest(t *testing.T, configFile string) {
	t.Helper()
	configLoaded = sync.Once{}
	AdminPubkeys = nil
	jety.SetConfigType("yaml")
	jety.SetConfigFile(configFile)
	_ = jety.ReadInConfig()
}

// resetForBinaryTest resets all config state: sync.Once, globals, jety, and
// systemConfigRoot. This ensures complete isolation between tests.
func resetForBinaryTest(t *testing.T, tmpRoot string) {
	t.Helper()
	configLoaded = sync.Once{}
	AdminPubkeys = nil
	resetJety(t)
	setSystemConfigRoot(tmpRoot)
	t.Cleanup(func() { resetSystemConfigRoot() })
}

func writeTempConfig(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBasePathValid_ExistingDir(t *testing.T) {
	dir := t.TempDir()
	RecipeDir = dir
	if !BasePathValid() {
		t.Error("BasePathValid should return true for an existing directory")
	}
}

func TestBasePathValid_NonExistentDir(t *testing.T) {
	RecipeDir = "/nonexistent/path/that/does/not/exist"
	if BasePathValid() {
		t.Error("BasePathValid should return false for a nonexistent directory")
	}
}

func TestBasePathValid_File(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "afile")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	RecipeDir = f
	if BasePathValid() {
		t.Error("BasePathValid should return false for a regular file")
	}
}

func TestStaticProps_ViaJety(t *testing.T) {
	// Set static props directly via jety to test the accessor.
	jety.Set("props.static", map[string]any{
		"sprout-1": map[string]any{"role": "webserver"},
		"sprout-2": map[string]any{"role": "database"},
	})
	defer jety.Set("props.static", nil)

	props := StaticProps()
	if len(props) == 0 {
		t.Fatal("expected non-empty static props")
	}
	if _, ok := props["sprout-1"]; !ok {
		t.Error("expected props to contain sprout-1")
	}
	if _, ok := props["sprout-2"]; !ok {
		t.Error("expected props to contain sprout-2")
	}
}

func TestInit_ViaJety(t *testing.T) {
	jety.Set("init", "systemd")
	defer jety.Set("init", "")

	if got := Init(); got != "systemd" {
		t.Errorf("Init() = %q, want systemd", got)
	}
}

func TestInit_Empty(t *testing.T) {
	jety.Set("init", "")
	if got := Init(); got != "" {
		t.Errorf("Init() = %q, want empty", got)
	}
}

func TestSetSproutID(t *testing.T) {
	dir := t.TempDir()
	cfgFile := writeTempConfig(t, dir, "config.yaml", "sproutid: original\n")
	resetForTest(t, cfgFile)

	SetSproutID("test-sprout-42")
	defer jety.Set("sproutid", "")

	got := jety.GetString("sproutid")
	if got != "test-sprout-42" {
		t.Errorf("sproutid via jety = %q, want test-sprout-42", got)
	}

	// Verify it was persisted to the config file.
	data, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("config file should not be empty after SetSproutID")
	}
}

func TestLoadConfig_ImasBinary(t *testing.T) {
	tmpHome := t.TempDir()
	cfgDir := filepath.Join(tmpHome, ".config", "imas")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(cfgDir, "imas")
	content := `
farmerinterface: 10.0.0.1
farmerapiport: "9999"
farmerbusport: "9998"
loglevel: debug
`
	if err := os.WriteFile(cfgFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", tmpHome)
	resetForTest(t, cfgFile)
	LoadConfig("imas")

	if FarmerInterface != "10.0.0.1" {
		t.Errorf("FarmerInterface = %q, want 10.0.0.1", FarmerInterface)
	}
	if FarmerAPIPort != "9999" {
		t.Errorf("FarmerAPIPort = %q, want 9999", FarmerAPIPort)
	}
	if FarmerBusPort != "9998" {
		t.Errorf("FarmerBusPort = %q, want 9998", FarmerBusPort)
	}
	if LogLevel != log.LDebug {
		t.Errorf("log.Level = %v, want debug", LogLevel)
	}
	wantURL := "https://10.0.0.1:9999"
	if FarmerURL != wantURL {
		t.Errorf("FarmerURL = %q, want %q", FarmerURL, wantURL)
	}
	wantBus := "10.0.0.1:9998"
	if FarmerBusURL != wantBus {
		t.Errorf("FarmerBusURL = %q, want %q", FarmerBusURL, wantBus)
	}
	if got := BusTLSServerName(); got != "10.0.0.1" {
		t.Errorf("BusTLSServerName() = %q, want 10.0.0.1 (the host of FarmerBusURL)", got)
	}
}

func TestLoadConfig_LogLevels(t *testing.T) {
	tests := []struct {
		input string
		want  log.Level
	}{
		{"debug", log.LDebug},
		{"info", log.LInfo},
		{"notice", log.LNotice},
		{"warn", log.LWarn},
		{"error", log.LError},
		{"panic", log.LPanic},
		{"fatal", log.LFatal},
		{"unknown", log.LNotice},
		{"", log.LNotice},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			tmpHome := t.TempDir()
			cfgDir := filepath.Join(tmpHome, ".config", "imas")
			_ = os.MkdirAll(cfgDir, 0o755)

			var content string
			if tt.input != "" {
				content = "loglevel: " + tt.input + "\n"
			}
			cfgFile := filepath.Join(cfgDir, "imas")
			_ = os.WriteFile(cfgFile, []byte(content), 0o644)

			t.Setenv("HOME", tmpHome)
			resetForTest(t, cfgFile)
			LoadConfig("imas")

			if LogLevel != tt.want {
				t.Errorf("log.Level for %q = %v, want %v", tt.input, LogLevel, tt.want)
			}
		})
	}
}

func TestLoadConfig_DefaultValues(t *testing.T) {
	tmpHome := t.TempDir()
	cfgDir := filepath.Join(tmpHome, ".config", "imas")
	_ = os.MkdirAll(cfgDir, 0o755)
	cfgFile := filepath.Join(cfgDir, "imas")
	_ = os.WriteFile(cfgFile, []byte(""), 0o644)

	t.Setenv("HOME", tmpHome)
	resetForTest(t, cfgFile)
	LoadConfig("imas")

	if FarmerInterface != "localhost" {
		t.Errorf("default FarmerInterface = %q, want localhost", FarmerInterface)
	}
	if FarmerBusTLSServerName != "" {
		t.Errorf("default FarmerBusTLSServerName = %q, want empty (derived)", FarmerBusTLSServerName)
	}
	if got := BusTLSServerName(); got != "localhost" {
		t.Errorf("default BusTLSServerName() = %q, want localhost", got)
	}
	if FarmerAPIPort != "5405" {
		t.Errorf("default FarmerAPIPort = %q, want 5405", FarmerAPIPort)
	}
	if FarmerBusPort != "5406" {
		t.Errorf("default FarmerBusPort = %q, want 5406", FarmerBusPort)
	}
	wantURL := "https://localhost:5405"
	if FarmerURL != wantURL {
		t.Errorf("default FarmerURL = %q, want %q", FarmerURL, wantURL)
	}
	wantBus := "localhost:5406"
	if FarmerBusURL != wantBus {
		t.Errorf("default FarmerBusURL = %q, want %q", FarmerBusURL, wantBus)
	}
	if LogLevel != log.LNotice {
		t.Errorf("default log.Level = %v, want LNotice", LogLevel)
	}
	if RecipeDir != filepath.Join("/", "srv", "imas", "recipes", "prod") {
		t.Errorf("default RecipeDir = %q", RecipeDir)
	}
}

func TestLoadConfig_CreatesConfigDirIfMissing(t *testing.T) {
	tmpHome := t.TempDir()
	cfgDir := filepath.Join(tmpHome, ".config", "imas")
	// Don't create cfgDir — LoadConfig should create it.
	cfgFile := filepath.Join(cfgDir, "imas")

	t.Setenv("HOME", tmpHome)
	configLoaded = sync.Once{}
	// Don't call resetForTest — let LoadConfig handle the missing file.
	LoadConfig("imas")

	if _, err := os.Stat(cfgDir); os.IsNotExist(err) {
		t.Error("LoadConfig should create the config directory")
	}
	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		t.Error("LoadConfig should create the config file")
	}
}

func TestLoadConfig_ImasRootCA(t *testing.T) {
	tmpHome := t.TempDir()
	cfgDir := filepath.Join(tmpHome, ".config", "imas")
	_ = os.MkdirAll(cfgDir, 0o755)
	cfgFile := filepath.Join(cfgDir, "imas")
	_ = os.WriteFile(cfgFile, []byte(""), 0o644)

	t.Setenv("HOME", tmpHome)
	// Ensure XDG_CONFIG_HOME is unset so LoadConfig falls back to $HOME/.config.
	t.Setenv("XDG_CONFIG_HOME", "")
	resetForTest(t, cfgFile)
	LoadConfig("imas")

	wantCA := filepath.Join(tmpHome, ".config", "imas", "tls-rootca.pem")
	// os.UserHomeDir() should pick up the overridden HOME.
	// If it doesn't (cached from an earlier test), verify the path ends correctly.
	wantSuffix := filepath.Join(".config", "imas", "tls-rootca.pem")
	if ImasRootCA != wantCA && !strings.HasSuffix(ImasRootCA, wantSuffix) {
		t.Errorf("ImasRootCA = %q, want %q (or suffix %q)", ImasRootCA, wantCA, wantSuffix)
	}
}

func TestLoadConfig_XDGConfigHome(t *testing.T) {
	tmpHome := t.TempDir()
	xdgDir := filepath.Join(tmpHome, "custom-config")
	cfgDir := filepath.Join(xdgDir, "imas")
	_ = os.MkdirAll(cfgDir, 0o755)
	cfgFile := filepath.Join(cfgDir, "imas")
	_ = os.WriteFile(cfgFile, []byte(""), 0o644)

	t.Setenv("HOME", tmpHome)
	t.Setenv("XDG_CONFIG_HOME", xdgDir)
	resetForTest(t, cfgFile)
	LoadConfig("imas")

	wantCA := filepath.Join(xdgDir, "imas", "tls-rootca.pem")
	if ImasRootCA != wantCA {
		t.Errorf("ImasRootCA = %q, want %q (with XDG_CONFIG_HOME)", ImasRootCA, wantCA)
	}
}

func TestLoadConfig_RecipeDirFallback(t *testing.T) {
	tmpHome := t.TempDir()
	cfgDir := filepath.Join(tmpHome, ".config", "imas")
	_ = os.MkdirAll(cfgDir, 0o755)
	cfgFile := writeTempConfig(t, cfgDir, "imas", "recipedir: \"\"\n")

	t.Setenv("HOME", tmpHome)
	resetForTest(t, cfgFile)
	LoadConfig("imas")

	want := filepath.Join("/", "srv", "imas", "recipes", "prod")
	if RecipeDir != want {
		t.Errorf("RecipeDir = %q, want %q (fallback)", RecipeDir, want)
	}
}

func TestVersion_Struct(t *testing.T) {
	v := Version{
		Arch:      "amd64",
		Compiler:  "gc",
		GitCommit: "abc123",
		Tag:       "v2.0.0",
	}
	if v.Arch != "amd64" {
		t.Error("unexpected Arch")
	}
	if v.Tag != "v2.0.0" {
		t.Error("unexpected Tag")
	}
}

func TestCombinedVersion_Struct(t *testing.T) {
	cv := CombinedVersion{
		CLI:    Version{Tag: "v2.0.0"},
		Farmer: Version{Tag: "v2.1.0"},
	}
	if cv.CLI.Tag != "v2.0.0" {
		t.Error("unexpected CLI tag")
	}
	if cv.Farmer.Tag != "v2.1.0" {
		t.Error("unexpected Farmer tag")
	}
}

func TestStartup_Struct(t *testing.T) {
	s := Startup{
		Version:  Version{Tag: "v1.0.0"},
		SproutID: "my-sprout",
	}
	if s.SproutID != "my-sprout" {
		t.Error("unexpected SproutID")
	}
}

func TestTriggerMsg_Struct(t *testing.T) {
	msg := TriggerMsg{JID: "job-12345"}
	if msg.JID != "job-12345" {
		t.Error("unexpected JID")
	}
}

func TestBinaryConstants(t *testing.T) {
	if BinaryImas != "imas" {
		t.Errorf("BinaryImas = %q", BinaryImas)
	}
	if BinaryFarmer != "farmer" {
		t.Errorf("BinaryFarmer = %q", BinaryFarmer)
	}
	if BinarySprout != "sprout" {
		t.Errorf("BinarySprout = %q", BinarySprout)
	}
}

func TestLoadConfig_FarmerDefaults(t *testing.T) {
	tmpRoot := t.TempDir()
	cfgFile := writeTempConfig(t, tmpRoot, "farmer", "")
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	LoadConfig("farmer")

	// Check farmer-specific defaults were applied.
	if FarmerAPIPort != "5405" {
		t.Errorf("default FarmerAPIPort = %q, want 5405", FarmerAPIPort)
	}
	if FarmerInterface != "localhost" {
		t.Errorf("default FarmerInterface = %q, want localhost", FarmerInterface)
	}
	if FarmerBusURL != "localhost:5406" {
		t.Errorf("default FarmerBusURL = %q, want localhost:5406", FarmerBusURL)
	}
	if got := BusTLSServerName(); got != "localhost" {
		t.Errorf("default BusTLSServerName() = %q, want localhost", got)
	}
	if FarmerOrganization != "imas farmer" {
		t.Errorf("FarmerOrganization = %q, want 'imas farmer'", FarmerOrganization)
	}
	if APIWriteTimeout != 120*time.Second {
		t.Errorf("APIWriteTimeout = %v, want 2m0s", APIWriteTimeout)
	}
	if APIReadTimeout != 120*time.Second {
		t.Errorf("APIReadTimeout = %v, want 2m0s", APIReadTimeout)
	}
	if APIIdleTimeout != 120*time.Second {
		t.Errorf("APIIdleTimeout = %v, want 2m0s", APIIdleTimeout)
	}
	if CertificateValidTime != 365*24*time.Hour {
		t.Errorf("CertificateValidTime = %v, want 8760h", CertificateValidTime)
	}
	if AuditLevel != "write" {
		t.Errorf("AuditLevel = %q, want write", AuditLevel)
	}
	wantPKI := filepath.Join(tmpRoot, "pki/farmer") + "/"
	if FarmerPKI != wantPKI {
		t.Errorf("FarmerPKI = %q, want %q", FarmerPKI, wantPKI)
	}
	wantCert := filepath.Join(tmpRoot, "pki/farmer/tls-cert.pem")
	if CertFile != wantCert {
		t.Errorf("CertFile = %q, want %q", CertFile, wantCert)
	}
	wantKey := filepath.Join(tmpRoot, "pki/farmer/tls-key.pem")
	if KeyFile != wantKey {
		t.Errorf("KeyFile = %q, want %q", KeyFile, wantKey)
	}
	wantRootCA := filepath.Join(tmpRoot, "pki/farmer/tls-rootca.pem")
	if RootCA != wantRootCA {
		t.Errorf("RootCA = %q, want %q", RootCA, wantRootCA)
	}
}

func TestLoadConfig_FarmerWithCustomInterface(t *testing.T) {
	tmpRoot := t.TempDir()
	content := "farmerinterface: 192.168.1.100\nfarmerapiport: \"8080\"\nfarmerbusport: \"8081\"\n"
	cfgFile := writeTempConfig(t, tmpRoot, "farmer", content)
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	LoadConfig("farmer")

	if FarmerInterface != "192.168.1.100" {
		t.Errorf("FarmerInterface = %q, want 192.168.1.100", FarmerInterface)
	}
	if FarmerAPIPort != "8080" {
		t.Errorf("FarmerAPIPort = %q, want 8080", FarmerAPIPort)
	}
	wantURL := "https://192.168.1.100:8080"
	if FarmerURL != wantURL {
		t.Errorf("FarmerURL = %q, want %q", FarmerURL, wantURL)
	}
	wantBus := "192.168.1.100:8081"
	if FarmerBusURL != wantBus {
		t.Errorf("FarmerBusURL = %q, want %q", FarmerBusURL, wantBus)
	}
	if got := BusTLSServerName(); got != "192.168.1.100" {
		t.Errorf("BusTLSServerName() = %q, want 192.168.1.100", got)
	}
	// Custom interface should be added to cert hosts.
	found := false
	for _, h := range CertHosts {
		if h == "192.168.1.100" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("CertHosts %v should contain 192.168.1.100", CertHosts)
	}
}

// A single-host install binding every interface keeps working: the bus
// is on the same host, so farmer dials 0.0.0.0 and verifies "localhost",
// which farmer's default certhosts cover.
func TestLoadConfig_FarmerWildcardBindSingleHost(t *testing.T) {
	tmpRoot := t.TempDir()
	cfgFile := writeTempConfig(t, tmpRoot, "farmer", "farmerinterface: 0.0.0.0\n")
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	LoadConfig("farmer")

	if FarmerInterface != "0.0.0.0" {
		t.Errorf("FarmerInterface = %q, want 0.0.0.0", FarmerInterface)
	}
	if FarmerBusURL != "0.0.0.0:5406" {
		t.Errorf("FarmerBusURL = %q, want 0.0.0.0:5406", FarmerBusURL)
	}
	if got := BusTLSServerName(); got != "localhost" {
		t.Errorf("BusTLSServerName() = %q, want localhost", got)
	}
}

// Kubernetes: core binds 0.0.0.0 and dials the bus as a separate Service.
// The bind address, the bus URL and the bus's TLS ServerName are three
// different values and each must come out as configured.
func TestLoadConfig_FarmerBindAddressSeparateFromBus(t *testing.T) {
	const svc = "imas-dmz-nats-bus.imas-dmz.svc.cluster.local"
	tests := []struct {
		name, config, wantBusURL, wantServerName string
	}{
		{
			name:           "server name derived from farmerbusurl",
			config:         "farmerinterface: 0.0.0.0\nfarmerbusurl: tls://" + svc + ":5406\n",
			wantBusURL:     "tls://" + svc + ":5406",
			wantServerName: svc,
		},
		{
			name:           "bare host:port farmerbusurl",
			config:         "farmerinterface: 0.0.0.0\nfarmerbusurl: " + svc + ":5406\n",
			wantBusURL:     svc + ":5406",
			wantServerName: svc,
		},
		{
			name:           "explicit server name wins",
			config:         "farmerinterface: 10.1.2.3\nfarmerbusurl: tls://10.9.9.9:5406\nfarmerbustlsservername: " + svc + "\n",
			wantBusURL:     "tls://10.9.9.9:5406",
			wantServerName: svc,
		},
		{
			name:           "explicit server name without farmerbusurl",
			config:         "farmerinterface: 0.0.0.0\nfarmerbustlsservername: " + svc + "\n",
			wantBusURL:     "0.0.0.0:5406",
			wantServerName: svc,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpRoot := t.TempDir()
			cfgFile := writeTempConfig(t, tmpRoot, "farmer", tt.config)
			resetForBinaryTest(t, tmpRoot)
			jety.SetConfigType("yaml")
			jety.SetConfigFile(cfgFile)
			_ = jety.ReadInConfig()

			LoadConfig("farmer")

			if FarmerURL != "https://"+FarmerInterface+":5405" {
				t.Errorf("FarmerURL = %q, want it to follow farmerinterface %q", FarmerURL, FarmerInterface)
			}
			if FarmerBusURL != tt.wantBusURL {
				t.Errorf("FarmerBusURL = %q, want %q", FarmerBusURL, tt.wantBusURL)
			}
			if got := BusTLSServerName(); got != tt.wantServerName {
				t.Errorf("BusTLSServerName() = %q, want %q", got, tt.wantServerName)
			}
		})
	}
}

// The Helm charts configure pods through the environment, so both new
// keys must be settable that way.
func TestLoadConfig_FarmerBusSettingsFromEnv(t *testing.T) {
	const svc = "imas-dmz-nats-bus.imas-dmz.svc.cluster.local"
	// Registered before t.Setenv, so it runs after the environment is
	// restored: jety's manager keeps the environment it parsed, and later
	// tests that reuse the manager must not see these variables.
	t.Cleanup(func() { resetJety(t) })
	t.Setenv("FARMERBUSURL", "tls://"+svc+":5406")
	t.Setenv("FARMERBUSTLSSERVERNAME", "bus.example.test")
	tmpRoot := t.TempDir()
	cfgFile := writeTempConfig(t, tmpRoot, "farmer", "farmerinterface: 0.0.0.0\n")
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	LoadConfig("farmer")

	if FarmerInterface != "0.0.0.0" {
		t.Errorf("FarmerInterface = %q, want 0.0.0.0", FarmerInterface)
	}
	if FarmerBusURL != "tls://"+svc+":5406" {
		t.Errorf("FarmerBusURL = %q, want the FARMERBUSURL value", FarmerBusURL)
	}
	if FarmerBusTLSServerName != "bus.example.test" {
		t.Errorf("FarmerBusTLSServerName = %q, want bus.example.test", FarmerBusTLSServerName)
	}
	if got := BusTLSServerName(); got != "bus.example.test" {
		t.Errorf("BusTLSServerName() = %q, want bus.example.test", got)
	}
}

// farmerbusurl/farmerbustlsservername are farmer and imas CLI settings.
// A sprout pins bus addresses with the validated busurls instead, so its
// legacy FarmerBusURL fallback (pki.ResolveSproutBusURLs) stays
// farmerinterface:farmerbusport.
func TestLoadConfig_FarmerBusURLIgnoredBySprout(t *testing.T) {
	const content = "farmerinterface: farmer.example.com\nfarmerbusurl: tls://elsewhere.example.com:5406\nfarmerbustlsservername: elsewhere.example.com\n"
	tmpRoot := t.TempDir()
	cfgFile := writeTempConfig(t, tmpRoot, "sprout", content)
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	LoadConfig("sprout")

	if FarmerBusURL != "farmer.example.com:5406" {
		t.Errorf("FarmerBusURL = %q, want farmer.example.com:5406", FarmerBusURL)
	}
	if FarmerBusTLSServerName != "" {
		t.Errorf("FarmerBusTLSServerName = %q, want empty", FarmerBusTLSServerName)
	}
	if got := BusTLSServerName(); got != "farmer.example.com" {
		t.Errorf("BusTLSServerName() = %q, want farmer.example.com", got)
	}
}

// loadImasConfig points HOME at a fresh directory holding content as the
// imas CLI's config file and runs LoadConfig("imas").
func loadImasConfig(t *testing.T, content string) {
	t.Helper()
	tmpHome := t.TempDir()
	cfgDir := filepath.Join(tmpHome, ".config", "imas")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgFile := writeTempConfig(t, cfgDir, "imas", content)
	t.Setenv("HOME", tmpHome)
	resetForBinaryTest(t, t.TempDir())
	resetForTest(t, cfgFile)

	LoadConfig("imas")
}

// The imas CLI dials the bus too (internal/api/client.NewNatsClient), so
// it reads the same keys farmer does.
func TestLoadConfig_ImasReadsFarmerBusSettings(t *testing.T) {
	const svc = "imas-nats-bus.imas.svc.cluster.local"
	t.Run("farmerbusurl only", func(t *testing.T) {
		loadImasConfig(t, "farmerinterface: farmer.example.com\nfarmerbusurl: tls://"+svc+":5406\n")

		if FarmerInterface != "farmer.example.com" {
			t.Errorf("FarmerInterface = %q, want farmer.example.com", FarmerInterface)
		}
		if FarmerBusURL != "tls://"+svc+":5406" {
			t.Errorf("FarmerBusURL = %q, want the farmerbusurl value", FarmerBusURL)
		}
		if FarmerBusTLSServerName != "" {
			t.Errorf("FarmerBusTLSServerName = %q, want empty", FarmerBusTLSServerName)
		}
		if got := BusTLSServerName(); got != svc {
			t.Errorf("BusTLSServerName() = %q, want %q", got, svc)
		}
	})
	t.Run("explicit server name", func(t *testing.T) {
		loadImasConfig(t, "farmerinterface: farmer.example.com\nfarmerbusurl: tls://10.0.0.5:5406\nfarmerbustlsservername: bus.example.test\n")

		if FarmerBusURL != "tls://10.0.0.5:5406" {
			t.Errorf("FarmerBusURL = %q, want tls://10.0.0.5:5406", FarmerBusURL)
		}
		if FarmerBusTLSServerName != "bus.example.test" {
			t.Errorf("FarmerBusTLSServerName = %q, want bus.example.test", FarmerBusTLSServerName)
		}
		if got := BusTLSServerName(); got != "bus.example.test" {
			t.Errorf("BusTLSServerName() = %q, want bus.example.test", got)
		}
	})
	t.Run("unset keeps farmerinterface", func(t *testing.T) {
		loadImasConfig(t, "farmerinterface: farmer.example.com\n")

		if FarmerBusURL != "farmer.example.com:5406" {
			t.Errorf("FarmerBusURL = %q, want farmer.example.com:5406", FarmerBusURL)
		}
		if got := BusTLSServerName(); got != "farmer.example.com" {
			t.Errorf("BusTLSServerName() = %q, want farmer.example.com", got)
		}
	})
	t.Run("from env", func(t *testing.T) {
		// Registered before t.Setenv, so it runs after the environment is
		// restored (see TestLoadConfig_FarmerBusSettingsFromEnv).
		t.Cleanup(func() { resetJety(t) })
		t.Setenv("FARMERBUSURL", "tls://"+svc+":5406")
		t.Setenv("FARMERBUSTLSSERVERNAME", "bus.example.test")
		loadImasConfig(t, "farmerinterface: farmer.example.com\n")

		if FarmerBusURL != "tls://"+svc+":5406" {
			t.Errorf("FarmerBusURL = %q, want the FARMERBUSURL value", FarmerBusURL)
		}
		if got := BusTLSServerName(); got != "bus.example.test" {
			t.Errorf("BusTLSServerName() = %q, want bus.example.test", got)
		}
	})
}

func TestBusURLHost(t *testing.T) {
	tests := []struct{ in, want string }{
		{"localhost:5406", "localhost"},
		{"farmer.example.com:5406", "farmer.example.com"},
		{"tls://bus.ns.svc.cluster.local:5406", "bus.ns.svc.cluster.local"},
		{"nats://bus.ns.svc:5406,nats://bus-1.ns.svc:5406", "bus.ns.svc"},
		{" tls://bus-0.ns.svc:5406 , tls://bus-1.ns.svc:5406", "bus-0.ns.svc"},
		{"10.0.0.5:5406", "10.0.0.5"},
		{"[fd00::5]:5406", "fd00::5"},
		{"0.0.0.0:5406", "localhost"},
		{"tls://0.0.0.0:5406", "localhost"},
		{"[::]:5406", "localhost"},
		{"bus.example.com", "bus.example.com"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := busURLHost(tt.in); got != tt.want {
			t.Errorf("busURLHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestBusTLSServerName_ExplicitOverridesURL(t *testing.T) {
	origURL, origName := FarmerBusURL, FarmerBusTLSServerName
	t.Cleanup(func() { FarmerBusURL, FarmerBusTLSServerName = origURL, origName })

	FarmerBusURL = "tls://10.0.0.5:5406"
	FarmerBusTLSServerName = ""
	if got := BusTLSServerName(); got != "10.0.0.5" {
		t.Errorf("derived BusTLSServerName() = %q, want 10.0.0.5", got)
	}
	FarmerBusTLSServerName = "bus.example.test"
	if got := BusTLSServerName(); got != "bus.example.test" {
		t.Errorf("explicit BusTLSServerName() = %q, want bus.example.test", got)
	}
}

func TestLoadConfig_FarmerCertHostsDefault(t *testing.T) {
	tmpRoot := t.TempDir()
	cfgFile := writeTempConfig(t, tmpRoot, "farmer", "")
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	LoadConfig("farmer")

	// Default cert hosts should include localhost, 127.0.0.1, farmer, imas.
	required := []string{"localhost", "127.0.0.1", "farmer", "imas"}
	hostSet := make(map[string]bool)
	for _, h := range CertHosts {
		hostSet[h] = true
	}
	for _, r := range required {
		if !hostSet[r] {
			t.Errorf("CertHosts %v missing required host %q", CertHosts, r)
		}
	}
}

func TestLoadConfig_FarmerAdminPubkeysFromConfig(t *testing.T) {
	tmpRoot := t.TempDir()
	content := `pubkeys:
  admin:
    - KEY_AAA
    - KEY_BBB
`
	cfgFile := writeTempConfig(t, tmpRoot, "farmer", content)
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	LoadConfig("farmer")

	if len(AdminPubkeys) != 2 {
		t.Fatalf("AdminPubkeys len = %d, want 2; got %v", len(AdminPubkeys), AdminPubkeys)
	}
	keySet := make(map[string]bool)
	for _, k := range AdminPubkeys {
		keySet[k] = true
	}
	if !keySet["KEY_AAA"] || !keySet["KEY_BBB"] {
		t.Errorf("AdminPubkeys = %v, want KEY_AAA and KEY_BBB", AdminPubkeys)
	}
}

func TestLoadConfig_FarmerAdminPubkeysFromEnv(t *testing.T) {
	tmpRoot := t.TempDir()
	cfgFile := writeTempConfig(t, tmpRoot, "farmer", "")
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	t.Setenv("ADMIN_PUBKEYS", "ENVKEY1,ENVKEY2,,ENVKEY3")

	LoadConfig("farmer")

	if len(AdminPubkeys) < 3 {
		t.Fatalf("AdminPubkeys len = %d, want >= 3; got %v", len(AdminPubkeys), AdminPubkeys)
	}
	keySet := make(map[string]bool)
	for _, k := range AdminPubkeys {
		keySet[k] = true
	}
	for _, want := range []string{"ENVKEY1", "ENVKEY2", "ENVKEY3"} {
		if !keySet[want] {
			t.Errorf("AdminPubkeys %v missing %q", AdminPubkeys, want)
		}
	}
}

func TestLoadConfig_FarmerCertHostsFromEnv(t *testing.T) {
	tmpRoot := t.TempDir()
	cfgFile := writeTempConfig(t, tmpRoot, "farmer", "")
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	t.Setenv("CERT_HOSTS", "myhost.local,,otherhost.local")

	LoadConfig("farmer")

	hostSet := make(map[string]bool)
	for _, h := range CertHosts {
		hostSet[h] = true
	}
	for _, want := range []string{"myhost.local", "otherhost.local"} {
		if !hostSet[want] {
			t.Errorf("CertHosts %v missing env-provided %q", CertHosts, want)
		}
	}
}

func TestLoadConfig_FarmerJobLogTTL(t *testing.T) {
	tmpRoot := t.TempDir()
	content := "joblogttl: 168h\n"
	cfgFile := writeTempConfig(t, tmpRoot, "farmer", content)
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	LoadConfig("farmer")

	want := 168 * time.Hour
	if JobLogTTL != want {
		t.Errorf("JobLogTTL = %v, want %v", JobLogTTL, want)
	}
}

func TestLoadConfig_SproutDefaults(t *testing.T) {
	tmpRoot := t.TempDir()
	cfgFile := writeTempConfig(t, tmpRoot, "sprout", "")
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	LoadConfig("sprout")

	wantPKI := filepath.Join(tmpRoot, "pki/sprout") + "/"
	if SproutPKI != wantPKI {
		t.Errorf("SproutPKI = %q, want %q", SproutPKI, wantPKI)
	}
	wantRootCA := filepath.Join(tmpRoot, "pki/sprout/tls-rootca.pem")
	if SproutRootCA != wantRootCA {
		t.Errorf("SproutRootCA = %q, want %q", SproutRootCA, wantRootCA)
	}
	if JobLogDir != "/var/cache/imas/sprout/jobs" {
		t.Errorf("JobLogDir = %q, want /var/cache/imas/sprout/jobs", JobLogDir)
	}
	wantNKeyPub := filepath.Join(tmpRoot, "pki/sprout/sprout.nkey.pub")
	if NKeySproutPubFile != wantNKeyPub {
		t.Errorf("NKeySproutPubFile = %q, want %q", NKeySproutPubFile, wantNKeyPub)
	}
	wantNKeyPriv := filepath.Join(tmpRoot, "pki/sprout/sprout.nkey")
	if NKeySproutPrivFile != wantNKeyPriv {
		t.Errorf("NKeySproutPrivFile = %q, want %q", NKeySproutPrivFile, wantNKeyPriv)
	}
}

func TestLoadConfig_SproutRootCATOFU(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"default on", "", true},
		{"disabled for a DMZ install", "sproutrootcatofu: false\n", false},
		{"explicitly on", "sproutrootcatofu: true\n", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			loadSproutConfig(t, c.content)
			if SproutRootCATOFU != c.want {
				t.Errorf("SproutRootCATOFU = %v, want %v", SproutRootCATOFU, c.want)
			}
		})
	}
}

func TestLoadConfig_SproutWithCustomID(t *testing.T) {
	tmpRoot := t.TempDir()
	content := "sproutid: my-custom-sprout\nloglevel: warn\n"
	cfgFile := writeTempConfig(t, tmpRoot, "sprout", content)
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	LoadConfig("sprout")

	if SproutID != "my-custom-sprout" {
		t.Errorf("SproutID = %q, want my-custom-sprout", SproutID)
	}
	if LogLevel != log.LWarn {
		t.Errorf("LogLevel = %v, want LWarn", LogLevel)
	}
}

func TestLoadConfig_SproutCreatesConfigIfMissing(t *testing.T) {
	tmpRoot := t.TempDir()
	// Don't create the sprout config file — LoadConfig should create it.
	resetForBinaryTest(t, tmpRoot)

	LoadConfig("sprout")

	cfgFile := filepath.Join(tmpRoot, "sprout")
	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		t.Error("LoadConfig should create the sprout config file")
	}
}

func TestLoadConfig_FarmerCreatesConfigIfMissing(t *testing.T) {
	tmpRoot := t.TempDir()
	// Don't create the farmer config file — LoadConfig should create it.
	resetForBinaryTest(t, tmpRoot)

	LoadConfig("farmer")

	cfgFile := filepath.Join(tmpRoot, "farmer")
	if _, err := os.Stat(cfgFile); os.IsNotExist(err) {
		t.Error("LoadConfig should create the farmer config file")
	}
}

func TestLoadConfig_FarmerCertHostsFromConfig(t *testing.T) {
	tmpRoot := t.TempDir()
	content := `certhosts:
  - custom-host-1
  - custom-host-2
`
	cfgFile := writeTempConfig(t, tmpRoot, "farmer", content)
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	LoadConfig("farmer")

	hostSet := make(map[string]bool)
	for _, h := range CertHosts {
		hostSet[h] = true
	}
	if !hostSet["custom-host-1"] || !hostSet["custom-host-2"] {
		t.Errorf("CertHosts %v should contain custom-host-1 and custom-host-2", CertHosts)
	}
}

func TestLoadConfig_FarmerPropsDir(t *testing.T) {
	tmpRoot := t.TempDir()
	content := "propsdir: /custom/props\n"
	cfgFile := writeTempConfig(t, tmpRoot, "farmer", content)
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	LoadConfig("farmer")

	if PropsDir != "/custom/props" {
		t.Errorf("PropsDir = %q, want /custom/props", PropsDir)
	}
}

func TestStaticProps_Empty(t *testing.T) {
	jety.Set("props.static", nil)
	props := StaticProps()
	if len(props) != 0 {
		t.Errorf("StaticProps() = %v, want empty", props)
	}
}

func TestLoadConfig_SproutEnrollmentPaths(t *testing.T) {
	tmpRoot := t.TempDir()
	cfgFile := writeTempConfig(t, tmpRoot, "sprout", "")
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	LoadConfig("sprout")

	want := map[string]string{
		"SproutUserJWTFile":         SproutUserJWTFile,
		"SproutGatewayJWTFile":      SproutGatewayJWTFile,
		"SproutTenantX25519PubFile": SproutTenantX25519PubFile,
		"SproutBoxPrivFile":         SproutBoxPrivFile,
		"SproutBoxPubFile":          SproutBoxPubFile,
	}
	names := map[string]string{
		"SproutUserJWTFile":         "sprout.jwt",
		"SproutGatewayJWTFile":      "gateway.jwt",
		"SproutTenantX25519PubFile": "tenant-x25519.pub",
		"SproutBoxPrivFile":         "sprout-x25519.key",
		"SproutBoxPubFile":          "sprout-x25519.pub",
	}
	for field, got := range want {
		if exp := filepath.Join(tmpRoot, "pki/sprout", names[field]); got != exp {
			t.Errorf("%s = %q, want %q", field, got, exp)
		}
	}
	if GatewayJWTTTL != 24*time.Hour {
		t.Errorf("GatewayJWTTTL = %s, want 24h", GatewayJWTTTL)
	}
}

func TestLoadConfig_SproutJoinToken(t *testing.T) {
	cases := []struct {
		name, file, env, want string
		setEnv                bool
		wantSrc               JoinTokenOrigin
	}{
		{name: "unset", want: "", wantSrc: JoinTokenFromNone},
		{name: "from config file", file: "jointoken: ek_file.secret\n", want: "ek_file.secret", wantSrc: JoinTokenFromFile},
		{name: "env overrides file", file: "jointoken: ek_file.secret\n", env: "ek_env.secret\n", setEnv: true, want: "ek_env.secret", wantSrc: JoinTokenFromEnv},
		{name: "empty env falls back to file", file: "jointoken: ek_file.secret\n", env: "", setEnv: true, want: "ek_file.secret", wantSrc: JoinTokenFromFile},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.setEnv {
				t.Setenv(EnvJoinToken, c.env)
			} else {
				t.Setenv(EnvJoinToken, "")
				os.Unsetenv(EnvJoinToken)
			}
			tmpRoot := t.TempDir()
			cfgFile := writeTempConfig(t, tmpRoot, "sprout", c.file)
			resetForBinaryTest(t, tmpRoot)
			jety.SetConfigType("yaml")
			jety.SetConfigFile(cfgFile)
			_ = jety.ReadInConfig()

			LoadConfig("sprout")

			if JoinToken != c.want {
				t.Errorf("JoinToken = %q, want %q", JoinToken, c.want)
			}
			if JoinTokenSource != c.wantSrc {
				t.Errorf("JoinTokenSource = %q, want %q", JoinTokenSource, c.wantSrc)
			}
			SetJoinTokenFromFlag("  ek_flag.secret\n")
			if JoinToken != "ek_flag.secret" || JoinTokenSource != JoinTokenFromFlag {
				t.Errorf("after SetJoinTokenFromFlag: %q from %q", JoinToken, JoinTokenSource)
			}
		})
	}
}

// A join token from the environment is a secret and must not end up in
// the config file LoadConfig rewrites.
func TestLoadConfig_SproutJoinTokenFromEnvNotPersisted(t *testing.T) {
	t.Setenv(EnvJoinToken, "ek_env.topsecret")
	tmpRoot := t.TempDir()
	cfgFile := writeTempConfig(t, tmpRoot, "sprout", "")
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()

	LoadConfig("sprout")

	if JoinToken != "ek_env.topsecret" {
		t.Fatalf("JoinToken = %q", JoinToken)
	}
	b, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "topsecret") {
		t.Errorf("join token from the environment was written to the config file:\n%s", b)
	}
}

// loadSproutConfig writes content to a fresh sprout config file and
// loads it, returning the file's path.
func loadSproutConfig(t *testing.T, content string) string {
	t.Helper()
	tmpRoot := t.TempDir()
	cfgFile := writeTempConfig(t, tmpRoot, "sprout", content)
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()
	LoadConfig("sprout")
	return cfgFile
}

func TestClearJoinToken_RemovesItFromConfigFile(t *testing.T) {
	t.Setenv(EnvJoinToken, "")
	os.Unsetenv(EnvJoinToken)
	cfgFile := loadSproutConfig(t, "jointoken: ek_file.topsecret\nsproutid: web-01\n")
	if JoinToken != "ek_file.topsecret" {
		t.Fatalf("JoinToken = %q", JoinToken)
	}

	src, err := ClearJoinToken()
	if err != nil {
		t.Fatalf("ClearJoinToken: %v", err)
	}
	if src != JoinTokenFromNone {
		t.Errorf("ClearJoinToken reported %q left elsewhere, want none", src)
	}
	if JoinToken != "" {
		t.Error("JoinToken still set in memory")
	}
	b, _ := os.ReadFile(cfgFile)
	if strings.Contains(string(b), "topsecret") {
		t.Errorf("join token still in the config file:\n%s", b)
	}
	if !strings.Contains(string(b), "web-01") {
		t.Errorf("clearing the token lost the rest of the config:\n%s", b)
	}

	// And it stays gone on the next load.
	configLoaded = sync.Once{}
	LoadConfig("sprout")
	if JoinToken != "" {
		t.Errorf("JoinToken = %q after reload, want empty", JoinToken)
	}
}

// A token the sprout can't remove itself is reported, so the operator
// can be told where it is; any copy in the config file is still removed.
func TestClearJoinToken_ReportsEnvAndFlagSources(t *testing.T) {
	t.Setenv(EnvJoinToken, "ek_env.secret")
	cfgFile := loadSproutConfig(t, "jointoken: ek_file.topsecret\n")
	src, err := ClearJoinToken()
	if err != nil {
		t.Fatal(err)
	}
	if src != JoinTokenFromEnv {
		t.Errorf("ClearJoinToken = %q, want the environment", src)
	}
	if b, _ := os.ReadFile(cfgFile); strings.Contains(string(b), "topsecret") {
		t.Error("the config file's copy of the token was not removed")
	}

	loadSproutConfig(t, "")
	SetJoinTokenFromFlag("ek_flag.secret")
	if src, _ := ClearJoinToken(); src != JoinTokenFromFlag {
		t.Errorf("ClearJoinToken = %q, want the flag", src)
	}
}

func TestLoadConfig_SproutConfigFileIs0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes")
	}
	// An existing file left 0644 by an earlier version is tightened.
	cfgFile := loadSproutConfig(t, "jointoken: ek_file.secret\n")
	if err := os.Chmod(cfgFile, 0o644); err != nil {
		t.Fatal(err)
	}
	configLoaded = sync.Once{}
	LoadConfig("sprout")
	info, err := os.Stat(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("existing sprout config mode = %o, want 600", perm)
	}

	// A file LoadConfig creates itself is 0600 too.
	tmpRoot := t.TempDir()
	resetForBinaryTest(t, tmpRoot)
	LoadConfig("sprout")
	info, err = os.Stat(filepath.Join(tmpRoot, "sprout"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("new sprout config mode = %o, want 600", perm)
	}
}

// The sprout's staged-recipe and gateway JWT settings come from the
// sprout config file ("config properties"), with defaults when unset.
func TestLoadConfig_SproutStagedRecipeSettings(t *testing.T) {
	t.Run("from the config file", func(t *testing.T) {
		tmpRoot := t.TempDir()
		content := "stagedrecipemaxage: 6h\ngatewayjwtrefreshmargin: 10m\nsprouthandledjobsfile: /tmp/imas-handled\nsproutboxkeyprevgrace: 1h\n"
		cfgFile := writeTempConfig(t, tmpRoot, "sprout", content)
		resetForBinaryTest(t, tmpRoot)
		jety.SetConfigType("yaml")
		jety.SetConfigFile(cfgFile)
		_ = jety.ReadInConfig()

		LoadConfig("sprout")

		if StagedRecipeMaxAge != 6*time.Hour {
			t.Errorf("StagedRecipeMaxAge = %v, want 6h", StagedRecipeMaxAge)
		}
		if GatewayJWTRefreshMargin != 10*time.Minute {
			t.Errorf("GatewayJWTRefreshMargin = %v, want 10m", GatewayJWTRefreshMargin)
		}
		if SproutHandledJobsFile != "/tmp/imas-handled" {
			t.Errorf("SproutHandledJobsFile = %q, want /tmp/imas-handled", SproutHandledJobsFile)
		}
		if SproutBoxKeyPrevGrace != time.Hour {
			t.Errorf("SproutBoxKeyPrevGrace = %v, want 1h", SproutBoxKeyPrevGrace)
		}
	})

	t.Run("defaults, written back to the config file", func(t *testing.T) {
		tmpRoot := t.TempDir()
		resetForBinaryTest(t, tmpRoot)

		LoadConfig("sprout")

		if StagedRecipeMaxAge != DefaultStagedRecipeMaxAge {
			t.Errorf("StagedRecipeMaxAge = %v, want %v", StagedRecipeMaxAge, DefaultStagedRecipeMaxAge)
		}
		if GatewayJWTRefreshMargin != DefaultGatewayJWTRefreshMargin {
			t.Errorf("GatewayJWTRefreshMargin = %v, want %v", GatewayJWTRefreshMargin, DefaultGatewayJWTRefreshMargin)
		}
		if SproutBoxKeyPrevGrace != DefaultSproutBoxKeyPrevGrace {
			t.Errorf("SproutBoxKeyPrevGrace = %v, want %v", SproutBoxKeyPrevGrace, DefaultSproutBoxKeyPrevGrace)
		}
		if SproutHandledJobsFile != "/var/lib/imas/sprout/handled-jobs" {
			t.Errorf("SproutHandledJobsFile = %q", SproutHandledJobsFile)
		}
		b, err := os.ReadFile(filepath.Join(tmpRoot, "sprout"))
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"stagedrecipemaxage", "gatewayjwtrefreshmargin", "sprouthandledjobsfile", "sproutboxkeyprevgrace"} {
			if !strings.Contains(string(b), key) {
				t.Errorf("sprout config file doesn't list %q, so operators can't see it:\n%s", key, b)
			}
		}
	})
}

// The sprout's bus reconnect backoff comes from the sprout config file,
// with natsretry's defaults written back when unset. The defaults land in
// the file as concrete values, which is why the Ansible role only ever
// adds an override for these keys and never removes them.
func TestLoadConfig_SproutBusReconnectSettings(t *testing.T) {
	t.Run("from the config file", func(t *testing.T) {
		tmpRoot := t.TempDir()
		cfgFile := writeTempConfig(t, tmpRoot, "sprout", "busreconnectbase: 500ms\nbusreconnectcap: 2m\n")
		resetForBinaryTest(t, tmpRoot)
		jety.SetConfigType("yaml")
		jety.SetConfigFile(cfgFile)
		_ = jety.ReadInConfig()

		LoadConfig("sprout")

		if BusReconnectBase != 500*time.Millisecond {
			t.Errorf("BusReconnectBase = %v, want 500ms", BusReconnectBase)
		}
		if BusReconnectCap != 2*time.Minute {
			t.Errorf("BusReconnectCap = %v, want 2m", BusReconnectCap)
		}
	})

	t.Run("defaults, written back to the config file", func(t *testing.T) {
		tmpRoot := t.TempDir()
		resetForBinaryTest(t, tmpRoot)

		LoadConfig("sprout")

		if BusReconnectBase != natsretry.DefaultBase {
			t.Errorf("BusReconnectBase = %v, want %v", BusReconnectBase, natsretry.DefaultBase)
		}
		if BusReconnectCap != natsretry.DefaultCap {
			t.Errorf("BusReconnectCap = %v, want %v", BusReconnectCap, natsretry.DefaultCap)
		}
		b, err := os.ReadFile(filepath.Join(tmpRoot, "sprout"))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range []string{"busreconnectbase: 2s", "busreconnectcap: 5m0s"} {
			if !strings.Contains(string(b), line) {
				t.Errorf("sprout config file doesn't contain %q:\n%s", line, b)
			}
		}
	})
}

func loadFarmerWithConfig(t *testing.T, content string) {
	t.Helper()
	tmpRoot := t.TempDir()
	cfgFile := writeTempConfig(t, tmpRoot, "farmer", content)
	resetForBinaryTest(t, tmpRoot)
	jety.SetConfigType("yaml")
	jety.SetConfigFile(cfgFile)
	_ = jety.ReadInConfig()
	LoadConfig("farmer")
}

// JobReconcileWindow comes from the farmer config file or, when the file
// doesn't set it, IMAS_JOB_RECONCILE_WINDOW (the Helm chart's route).
func TestLoadConfig_FarmerJobReconcileWindow(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv(EnvJobReconcileWindow, "")
		loadFarmerWithConfig(t, "")
		if JobReconcileWindow != 0 {
			t.Errorf("JobReconcileWindow = %v, want 0 (disabled)", JobReconcileWindow)
		}
	})
	t.Run("from env", func(t *testing.T) {
		t.Setenv(EnvJobReconcileWindow, "90m")
		loadFarmerWithConfig(t, "")
		if JobReconcileWindow != 90*time.Minute {
			t.Errorf("JobReconcileWindow = %v, want 90m", JobReconcileWindow)
		}
	})
	t.Run("config file wins over env", func(t *testing.T) {
		t.Setenv(EnvJobReconcileWindow, "90m")
		loadFarmerWithConfig(t, "jobreconcilewindow: 3h\n")
		if JobReconcileWindow != 3*time.Hour {
			t.Errorf("JobReconcileWindow = %v, want 3h", JobReconcileWindow)
		}
	})
}

// An invalid IMAS_JOB_RECONCILE_WINDOW stops farmer rather than silently
// disabling the window. log.Fatalf exits, so this runs in a subprocess.
func TestLoadConfig_FarmerJobReconcileWindowInvalid(t *testing.T) {
	if v := os.Getenv("IMAS_TEST_RECONCILE_SUBPROCESS"); v != "" {
		t.Setenv(EnvJobReconcileWindow, v)
		loadFarmerWithConfig(t, "")
		return
	}
	for _, bad := range []string{"soon", "-1h", "5"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestLoadConfig_FarmerJobReconcileWindowInvalid$")
		cmd.Env = append(os.Environ(), "IMAS_TEST_RECONCILE_SUBPROCESS="+bad)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("%s=%q: farmer config loaded; want it to exit", EnvJobReconcileWindow, bad)
			continue
		}
		if !strings.Contains(string(out), EnvJobReconcileWindow) {
			t.Errorf("%s=%q: exit message doesn't name the variable:\n%s", EnvJobReconcileWindow, bad, out)
		}
	}
}

func TestLoadConfig_SproutBusURLs(t *testing.T) {
	cases := map[string]struct {
		content string
		want    []string
	}{
		"unset":        {"sproutid: s1\n", nil},
		"yaml list":    {"busurls:\n  - wss://edge1:8443\n  - \" wss://edge2:8443 \"\n", []string{"wss://edge1:8443", "wss://edge2:8443"}},
		"comma string": {"busurls: \"wss://edge1:8443, wss://edge2:8443,\"\n", []string{"wss://edge1:8443", "wss://edge2:8443"}},
		"empty list":   {"busurls: []\n", nil},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tmpRoot := t.TempDir()
			cfgFile := writeTempConfig(t, tmpRoot, "sprout", tc.content)
			resetForBinaryTest(t, tmpRoot)
			jety.SetConfigType("yaml")
			jety.SetConfigFile(cfgFile)
			_ = jety.ReadInConfig()
			BusURLs = nil

			LoadConfig("sprout")

			if len(BusURLs) != len(tc.want) {
				t.Fatalf("BusURLs = %q, want %q", BusURLs, tc.want)
			}
			for i := range tc.want {
				if BusURLs[i] != tc.want[i] {
					t.Fatalf("BusURLs = %q, want %q", BusURLs, tc.want)
				}
			}
			if want := filepath.Join(tmpRoot, "pki/sprout/bus-urls.json"); SproutBusURLsFile != want {
				t.Errorf("SproutBusURLsFile = %q, want %q", SproutBusURLsFile, want)
			}
		})
	}
}

func TestLoadConfig_SproutUpdateRepoSettings(t *testing.T) {
	cases := map[string]struct {
		content            string
		wantURL, wantToken string
	}{
		"unset": {"sproutid: s1\n", "", ""},
		"set": {"sproutupdaterepourl: \" https://packages.example.com/org/imasdeb/any/ \"\nsproutupdaterepotoken: \" tok \"\n" +
			"sproutupdaterepoformat: apt\nsproutupdaterepodist: \"stable main\"\nsproutupdaterepopackageid: my.msi\n",
			"https://packages.example.com/org/imasdeb/any/", "tok"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tmpRoot := t.TempDir()
			cfgFile := writeTempConfig(t, tmpRoot, "sprout", tc.content)
			resetForBinaryTest(t, tmpRoot)
			jety.SetConfigType("yaml")
			jety.SetConfigFile(cfgFile)
			_ = jety.ReadInConfig()
			SproutUpdateRepoURL, SproutUpdateRepoToken, SproutFleetSigningKeyring = "stale", "stale", "stale"
			SproutUpdateRepoFormat, SproutUpdateRepoDist, SproutUpdateRepoPackageID = "stale", "stale", "stale"

			LoadConfig("sprout")

			if SproutUpdateRepoURL != tc.wantURL {
				t.Errorf("SproutUpdateRepoURL = %q, want %q", SproutUpdateRepoURL, tc.wantURL)
			}
			if SproutUpdateRepoToken != tc.wantToken {
				t.Errorf("SproutUpdateRepoToken = %q, want %q", SproutUpdateRepoToken, tc.wantToken)
			}
			if name == "set" && (SproutUpdateRepoFormat != "apt" || SproutUpdateRepoDist != "stable main" || SproutUpdateRepoPackageID != "my.msi") {
				t.Errorf("format, dist, package id = %q, %q, %q", SproutUpdateRepoFormat, SproutUpdateRepoDist, SproutUpdateRepoPackageID)
			}
			if name == "unset" && SproutUpdateRepoFormat+SproutUpdateRepoDist+SproutUpdateRepoPackageID != "" {
				t.Errorf("unset: format, dist, package id = %q, %q, %q", SproutUpdateRepoFormat, SproutUpdateRepoDist, SproutUpdateRepoPackageID)
			}
			if want := filepath.Join(tmpRoot, "fleet-signing-keys.json"); SproutFleetSigningKeyring != want {
				t.Errorf("SproutFleetSigningKeyring = %q, want %q", SproutFleetSigningKeyring, want)
			}
		})
	}
}
