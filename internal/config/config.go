package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/taigrr/jety"
	"github.com/yogzblr/imas/internal/log"
)

const ImasExt = "imas"

var BuildInfo Version

var configLoaded sync.Once

// systemConfigRoot is the root directory for farmer/sprout config files.
// Defaults to "/etc/imas". Tests can override via setSystemConfigRoot.
var systemConfigRoot = "/etc/imas"

// EnvJobReconcileWindow sets JobReconcileWindow on farmer when the config
// file doesn't (e.g. from the Helm chart; see deploy/farmer).
const EnvJobReconcileWindow = "IMAS_JOB_RECONCILE_WINDOW"

// Sprout setting defaults; see GatewayJWTRefreshMargin and
// StagedRecipeMaxAge.
const (
	DefaultGatewayJWTRefreshMargin = 5 * time.Minute
	DefaultStagedRecipeMaxAge      = time.Hour
)

// setSystemConfigRoot overrides the config root for testing.
func setSystemConfigRoot(root string) {
	systemConfigRoot = root
}

// resetSystemConfigRoot restores the default config root.
func resetSystemConfigRoot() {
	systemConfigRoot = "/etc/imas"
}

var (
	AdminPubkeys         []string
	APIIdleTimeout       time.Duration
	APIReadTimeout       time.Duration
	APIWriteTimeout      time.Duration
	AuditLevel           string
	AuditLogDir          string
	CacheDir             string
	CertFile             string
	CertHosts            []string
	CertificateValidTime time.Duration
	ConfigRoot           string
	// FarmerAPIPort is the port for the farmer's HTTPS server.
	// This server handles initial sprout enrollment only (certificate
	// distribution and NKey registration). All post-enrollment communication
	// happens over the NATS bus.
	FarmerAPIPort string

	FarmerBusURL  string
	FarmerBusPort string
	// FarmerWSPort is the port for nats-server's websocket listener —
	// what Envoy's jwt_authn-gated route proxies sprout wss:// connections
	// to, per docs/design/imas-envoy-enrollment-design.md. Distinct from
	// FarmerBusPort (the plain TCP NATS listener imas CLI/farmer-to-farmer
	// connections still use).
	FarmerWSPort          string
	FarmerInterface       string
	FarmerOrganization    string
	FarmerPKI             string
	FarmerURL             string
	ImasRootCA            string
	CohortRefreshInterval time.Duration
	JobLogDir             string
	JobLogTTL             time.Duration
	PropsDir              string
	KeyFile               string
	LogLevel              log.Level
	NKeyFarmerPrivFile    string
	NKeyFarmerPubFile     string
	NKeySproutPrivFile    string
	NKeySproutPubFile     string
	RecipeDir             string
	RootCA                string
	RootCAPriv            string
	SproutID              string
	SproutPKI             string
	SproutRootCA          string

	// SproutRootCATOFU is whether a sprout with no SproutRootCA file may
	// fetch one by trust on first use (pki.FetchRootCA, an unverified
	// GET of farmer's /auth/cert/). True by default for sprouts that
	// reach farmer directly. A sprout behind the DMZ Envoy sets
	// "sproutrootcatofu: false": its enrollment tooling (e.g. the
	// Ansible playbook that also delivers the join token) pre-provisions
	// SproutRootCA with the CA that issued Envoy's DMZ edge certificate,
	// and a missing file is then an error rather than a reason to trust
	// whatever answers first. See docs/design/imas-envoy-enrollment-design.md.
	SproutRootCATOFU bool

	// SproutFleetSigningJWKS is where a sprout pins the imas-fleet-signing
	// public key set it received at enrollment (POST /v1/enroll's
	// fleet_signing_jwks, design doc §2.5) — next to SproutRootCA, with
	// the same write-once lifecycle (pki.PinFleetSigningKeys). The
	// selfupdate ingredient verifies every release against it.
	SproutFleetSigningJWKS string

	// JoinToken is the "{key_id}.{secret}" enrollment key a sprout
	// presents to POST /v1/enroll the first time it enrolls
	// (docs/design/imas-envoy-enrollment-design.md). Whoever provisions
	// the sprout (e.g. an Ansible playbook) picks the source: the
	// "jointoken" key in the sprout config file, the IMAS_JOIN_TOKEN
	// environment variable (which wins over the file), or the sprout's
	// --join-token flag (which wins over both; cmd/sprout sets it with
	// SetJoinTokenFromFlag after LoadConfig). It is a secret, so it is
	// never written back to the config file by LoadConfig. It has no use
	// once the sprout has enrolled (every later call is a proof-of-
	// possession replay or refresh), so the sprout removes it from the
	// config file itself with ClearJoinToken.
	JoinToken string
	// JoinTokenSource records where JoinToken came from.
	JoinTokenSource JoinTokenOrigin

	// SproutUserJWTFile, SproutGatewayJWTFile and
	// SproutTenantX25519PubFile are where a sprout persists the NATS User
	// JWT, the gateway JWT and the tenant's X25519 box public key from
	// POST /v1/enroll's response — next to NKeySproutPrivFile and
	// SproutRootCA (pki.PersistEnrollment). SproutUserJWTFile is written
	// last, so its presence is what marks the sprout as enrolled.
	SproutUserJWTFile         string
	SproutGatewayJWTFile      string
	SproutTenantX25519PubFile string

	// SproutBusURLsFile ("sproutbusurlsfile", sprout only) is where a
	// sprout persists POST /v1/enroll's nats_urls, the bus addresses
	// farmer told it to connect to (farmer's SproutBusURLs), next to the
	// User JWT and gateway JWT (pki.PersistEnrollment). pki.LoadSproutBus
	// connects to them in preference to FarmerBusURL.
	SproutBusURLsFile string

	// BusURLs ("busurls" in the sprout config file, sprout only) pins the
	// bus addresses a sprout connects to, overriding both the enrolled
	// nats_urls (SproutBusURLsFile) and the legacy FarmerBusURL: for
	// installs that don't want the address farmer hands out at
	// enrollment, or that enrolled before farmer handed one out. A YAML
	// list or a comma-separated string. Empty by default.
	BusURLs []string

	// SproutBoxPrivFile/SproutBoxPubFile hold the sprout's own X25519
	// box keypair (docs/design/imas-payload-encryption-design.md,
	// "Bootstrap"), generated locally and once (pki.EnsureSproutBoxKey).
	// The private half never leaves the sprout.
	SproutBoxPrivFile string
	SproutBoxPubFile  string

	// GatewayJWTTTL bounds how long a minted gateway JWT
	// (internal/gatewayjwt) stays valid. Short by design: Envoy's
	// jwt_authn has no live revocation check of its own, so this expiry
	// is what makes a revoked sprout's gateway JWT age out promptly —
	// ongoing per-connection authorization is nats-server's Account/User
	// JWT model's job, not Envoy's.
	GatewayJWTTTL time.Duration

	// GatewayJWTRefreshMargin ("gatewayjwtrefreshmargin", sprout only) is
	// how much lifetime a sprout's gateway JWT must have left for it to be
	// sent on a GET /files/ download as is; with less, the sprout refreshes
	// it first (pki.FetchFarmerFile). Non-positive values fall back to
	// DefaultGatewayJWTRefreshMargin. A margin at or above the token's TTL
	// makes every download refresh.
	GatewayJWTRefreshMargin time.Duration

	// StagedRecipeMaxAge ("stagedrecipemaxage", sprout only) is how old a
	// staged recipe a sprout pulls (on startup, reconnect or a farmer
	// resync nudge) may be, measured from farmer's dispatch time, for the
	// sprout to still cook it when it missed the original push. Older ones
	// are skipped. Non-positive values fall back to
	// DefaultStagedRecipeMaxAge.
	StagedRecipeMaxAge time.Duration

	// JobReconcileWindow ("jobreconcilewindow" in the farmer config file,
	// or the IMAS_JOB_RECONCILE_WINDOW environment variable when the file
	// doesn't set it; farmer only) is how long after dispatch a job may
	// start on its sprout and still be recorded. A job whose start is
	// reported later (a sprout that missed the push and cooked the staged
	// copy much later) is not reconciled: farmer drops all of its events
	// and marks it "expired". 0 (the default) records every job whenever
	// it starts. Set it to at least the largest stagedrecipemaxage in the
	// fleet, or late jobs will run on sprouts without being recorded.
	JobReconcileWindow time.Duration

	// SproutHandledJobsFile ("sprouthandledjobsfile", sprout only) lists
	// the IDs of the recipe jobs the sprout most recently handled, pushed
	// or pulled, so a pull never cooks a job twice, across restarts too.
	SproutHandledJobsFile string

	// GatewayTransitKeyName is the OpenBao Transit key name
	// internal/gatewayjwt signs gateway JWTs with.
	GatewayTransitKeyName string

	// BoxKeyGraceDuration bounds how long a sprout's previous X25519 box
	// public key stays valid after a sprout-initiated rotation
	// (internal/pki/boxkeys.go), so payloads already in flight when a
	// rotation happens still decrypt correctly. See
	// docs/design/imas-payload-encryption-design.md's "Key rotation".
	BoxKeyGraceDuration time.Duration

	// SproutBusURLs are the externally-reachable wss:// addresses (fronted
	// by Envoy's jwt_authn-gated route — see
	// docs/design/imas-envoy-enrollment-design.md) an enrolling sprout is
	// told to connect to, returned as nats_urls in the enrollment response
	// (cloudxp-machine-manager-api-design.md §3.2). Comma-separated in
	// config/env; empty by default, in which case the enrollment handler
	// falls back to deriving a single-node URL from
	// FarmerInterface/FarmerWSPort for local/dev use.
	SproutBusURLs []string

	// PXCDSN is the GORM MySQL DSN for the shared Percona XtraDB Cluster's
	// `farmer` schema (PKI, props/facts, RBAC — see internal/pxc,
	// internal/props/store.go, internal/pki/store.go,
	// internal/rbac/store.go), e.g.
	// "farmer_svc:pass@tcp(pxc-cluster:3306)/farmer?parseTime=true".
	PXCDSN string

	// ValkeyAddrs is the comma-separated list of Valkey node addresses
	// (host:port) backing the connection-state heartbeat (see
	// internal/heartbeat) and the enrollment/refresh replay cache (see
	// internal/pki/replaycache.go).
	ValkeyAddrs string

	// S3Endpoint/S3AccessKeyID/S3SecretAccessKey/S3UseSSL/S3Bucket
	// configure the object-storage backend recipes are read from (see
	// internal/objectstore, internal/cook/store.go).
	S3Endpoint        string
	S3AccessKeyID     string
	S3SecretAccessKey string
	S3UseSSL          bool
	S3Bucket          string

	// S3JobBucket is the bucket farmer's job logs are stored in (see
	// internal/jobs/store.go), on the same endpoint and credentials as
	// S3Bucket. It must be a different bucket: GET /files/<key>
	// (internal/api/handlers/recipes.go) serves any key in the recipe
	// bucket to any authenticated caller, so job logs sharing it would be
	// readable across sprouts and tenants.
	S3JobBucket string
)

// Binary represents the type of imas binary being configured.
type Binary string

const (
	BinaryImas   Binary = "imas"
	BinaryFarmer Binary = "farmer"
	BinarySprout Binary = "sprout"
)

func LoadConfig(binary string) {
	configLoaded.Do(func() {
		jety.SetConfigType("yaml")
		switch binary {
		case "imas":
			dirname, err := os.UserHomeDir()
			if err != nil {
				log.Fatal(err)
			}
			cfgPath := filepath.Join(dirname, ".config/imas/")
			jety.SetConfigFile(filepath.Join(cfgPath, "imas"))
		case "farmer":
			jety.SetConfigFile(filepath.Join(systemConfigRoot, "farmer"))
		case "sprout":
			jety.SetConfigFile(filepath.Join(systemConfigRoot, "sprout"))
		}
		err := jety.ReadInConfig()

		if errors.Is(err, jety.ErrConfigFileNotFound) || errors.Is(err, jety.ErrConfigFileEmpty) {
			log.Println("Config file not found, will create default config")
			switch binary {
			case "imas":
				dirname, errHomeDir := os.UserHomeDir()
				if errHomeDir != nil {
					log.Fatal(errHomeDir)
				}
				cfgPath := filepath.Join(dirname, ".config/imas/")
				if mkErr := os.MkdirAll(cfgPath, 0o755); mkErr != nil {
					log.Fatal(mkErr)
				}
				cfgFile := filepath.Join(cfgPath, "imas")
				_, err = os.Create(cfgFile)
				if err != nil {
					log.Fatal(err)
				}
			case "farmer":
				if mkErr := os.MkdirAll(systemConfigRoot, 0o755); mkErr != nil {
					log.Fatal(mkErr)
				}
				cfgFile := filepath.Join(systemConfigRoot, "farmer")
				_, err = os.Create(cfgFile)
				if err != nil {
					log.Fatal(err)
				}
			case "sprout":
				if mkErr := os.MkdirAll(systemConfigRoot, 0o755); mkErr != nil {
					log.Fatal(mkErr)
				}
				cfgFile := filepath.Join(systemConfigRoot, "sprout")
				_, err = os.Create(cfgFile)
				if err != nil {
					log.Fatal(err)
				}
			}
		} else if err != nil {
			log.Printf("%T\n", err)
			panic(fmt.Errorf("fatal error config file: %w", err))
		}
		jety.SetDefault("loglevel", "info")
		jety.SetDefault("cachedir", "/var/cache/imas/sprout/files/provided")
		jety.SetDefault("configroot", systemConfigRoot+"/")
		jety.SetDefault("recipedir", filepath.Join("/", "srv", "imas", "recipes", "prod"))
		jety.SetDefault("farmerinterface", "localhost")
		jety.SetDefault("farmerapiport", "5405")
		jety.SetDefault("farmerbusport", "5406")
		jety.SetDefault("farmerwsport", "5407")
		switch binary {
		case "imas":
			dirname, err := os.UserHomeDir()
			if err != nil {
				log.Fatal(err)
			}
			configDir := os.Getenv("XDG_CONFIG_HOME")
			if configDir == "" {
				configDir = filepath.Join(dirname, ".config")
			}
			certPath := filepath.Join(configDir, "imas/tls-rootca.pem")
			jety.Set("imasrootca", certPath)
		case "farmer":
			jety.SetDefault("apiwritetimeout", 120*time.Second)
			jety.SetDefault("apireadtimeout", 120*time.Second)
			jety.SetDefault("apiidletimeout", 120*time.Second)
			jety.SetDefault("certificatevalidtime", 365*24*time.Hour)
			jety.SetDefault("certfile", filepath.Join(systemConfigRoot, "pki/farmer/tls-cert.pem"))
			jety.SetDefault("farmerpki", filepath.Join(systemConfigRoot, "pki/farmer")+"/")
			jety.SetDefault("keyfile", filepath.Join(systemConfigRoot, "pki/farmer/tls-key.pem"))
			jety.SetDefault("auditlogdir", "/var/log/imas/audit")
			jety.SetDefault("auditlevel", "write")
			jety.SetDefault("joblogdir", "/var/cache/imas/farmer/jobs")
			jety.SetDefault("joblogttl", 30*24*time.Hour) // 30 days default
			jety.SetDefault("cohortrefreshinterval", 5*time.Minute)
			jety.SetDefault("propsdir", "/var/cache/imas/farmer/props")
			jety.SetDefault("nkeyfarmerpubfile", filepath.Join(systemConfigRoot, "pki/farmer/farmer.nkey.pub"))
			jety.SetDefault("nkeyfarmerprivfile", filepath.Join(systemConfigRoot, "pki/farmer/farmer.nkey"))
			jety.SetDefault("rootca", filepath.Join(systemConfigRoot, "pki/farmer/tls-rootca.pem"))
			jety.SetDefault("rootcapriv", filepath.Join(systemConfigRoot, "pki/farmer/tls-rootca-key.pem"))
			jety.SetDefault("farmerorganization", "imas farmer")
			jety.SetDefault("gatewayjwtttl", 24*time.Hour)
			jety.SetDefault("gatewaytransitkeyname", "imas-gateway-jwt")
			jety.SetDefault("boxkeygraceduration", 24*time.Hour)
			jety.SetDefault("s3usessl", true)
			JobLogDir = jety.GetString("joblogdir")
			JobLogTTL = jety.GetDuration("joblogttl")
			PropsDir = jety.GetString("propsdir")
			CertHosts = jety.GetStringSlice("certhosts")

			// PXC/Valkey/S3 connection settings are deployment secrets, not
			// meaningful YAML defaults — like ADMIN_PUBKEYS/CERT_HOSTS below,
			// they're read from the environment when the config file doesn't
			// set them, rather than given a default value.
			if jety.GetString("pxcdsn") == "" {
				if v, found := os.LookupEnv("IMAS_PXC_DSN"); found {
					jety.Set("pxcdsn", v)
				}
			}
			if jety.GetString("valkeyaddrs") == "" {
				if v, found := os.LookupEnv("IMAS_VALKEY_ADDRS"); found {
					jety.Set("valkeyaddrs", v)
				}
			}
			if jety.GetString("s3endpoint") == "" {
				if v, found := os.LookupEnv("IMAS_S3_ENDPOINT"); found {
					jety.Set("s3endpoint", v)
				}
			}
			if jety.GetString("s3accesskeyid") == "" {
				if v, found := os.LookupEnv("IMAS_S3_ACCESS_KEY_ID"); found {
					jety.Set("s3accesskeyid", v)
				}
			}
			if jety.GetString("s3secretaccesskey") == "" {
				if v, found := os.LookupEnv("IMAS_S3_SECRET_ACCESS_KEY"); found {
					jety.Set("s3secretaccesskey", v)
				}
			}
			if jety.GetString("s3bucket") == "" {
				if v, found := os.LookupEnv("IMAS_S3_BUCKET"); found {
					jety.Set("s3bucket", v)
				}
			}
			if jety.GetString("s3jobbucket") == "" {
				if v, found := os.LookupEnv("IMAS_S3_JOB_BUCKET"); found {
					jety.Set("s3jobbucket", v)
				}
			}
			if jety.GetDuration("jobreconcilewindow") == 0 {
				if v, found := os.LookupEnv(EnvJobReconcileWindow); found && v != "" {
					d, err := time.ParseDuration(v)
					if err != nil || d < 0 {
						log.Fatalf("%s=%q: want a non-negative duration such as 2h or 90m", EnvJobReconcileWindow, v)
					}
					jety.Set("jobreconcilewindow", d)
				}
			}
			JobReconcileWindow = jety.GetDuration("jobreconcilewindow")
			if JobReconcileWindow < 0 {
				log.Fatalf("jobreconcilewindow = %s: must not be negative", JobReconcileWindow)
			}
			if len(jety.GetStringSlice("sproutbusurls")) == 0 {
				if v, found := os.LookupEnv("IMAS_SPROUT_BUS_URLS"); found {
					urls := []string{}
					for _, u := range strings.Split(v, ",") {
						if u != "" {
							urls = append(urls, u)
						}
					}
					jety.Set("sproutbusurls", urls)
				}
			}

			AdminPubKeys := jety.GetStringMap("pubkeys")
			if len(AdminPubKeys) == 0 {
				if keyList, found := os.LookupEnv("ADMIN_PUBKEYS"); found {
					pubkeys := strings.Split(keyList, ",")
					adminSet := make(map[string]any)
					keys := []any{}
					for _, v := range pubkeys {
						if v != "" {
							keys = append(keys, v)
						}
					}
					adminSet["admin"] = keys
					jety.Set("pubkeys", adminSet)
				}
			}
			AdminPubKeys = jety.GetStringMap("pubkeys")
			if len(CertHosts) == 0 {
				if hostList, found := os.LookupEnv("CERT_HOSTS"); found {
					hosts := strings.Split(hostList, ",")
					cleanHosts := []string{}
					for _, v := range hosts {
						if v != "" {
							cleanHosts = append(cleanHosts, v)
						}
					}
					jety.Set("certhosts", cleanHosts)
				}
			}
			if AdminPubKeys["admin"] != nil {
				anyKeys, ok := AdminPubKeys["admin"].([]any)
				if !ok {
					log.Fatal("pubkeys > admin is not a slice")
				}
				for _, v := range anyKeys {
					if v, ok := v.(string); ok {
						AdminPubkeys = append(AdminPubkeys, v)
					}
				}

			}
			hosts := map[string]bool{"localhost": true, "127.0.0.1": true, "farmer": true, "imas": true}
			fi := jety.GetString("farmerinterface")
			if _, ok := hosts[fi]; fi != "" && !ok {
				hosts[fi] = true
			}
			chosts := []string{}
			for k := range hosts {
				chosts = append(chosts, k)
			}
			jety.SetDefault("certhosts", chosts)
			CertHosts = jety.GetStringSlice("certhosts")

		case "sprout":
			jety.SetDefault("sproutid", "")
			jety.SetDefault("sproutpki", filepath.Join(systemConfigRoot, "pki/sprout")+"/")
			jety.SetDefault("sproutrootca", filepath.Join(systemConfigRoot, "pki/sprout/tls-rootca.pem"))
			jety.SetDefault("sproutrootcatofu", true)
			jety.SetDefault("sproutfleetsigningjwks", filepath.Join(systemConfigRoot, "pki/sprout/fleet-signing-jwks.json"))
			jety.SetDefault("nkeysproutpubfile", filepath.Join(systemConfigRoot, "pki/sprout/sprout.nkey.pub"))
			jety.SetDefault("joblogdir", "/var/cache/imas/sprout/jobs")
			jety.SetDefault("joblogttl", 30*24*time.Hour) // 30 days default
			jety.SetDefault("nkeysproutprivfile", filepath.Join(systemConfigRoot, "pki/sprout/sprout.nkey"))
			jety.SetDefault("cachedir", "/var/cache/imas/sprout/files/provided")
			jety.SetDefault("sproutuserjwtfile", filepath.Join(systemConfigRoot, "pki/sprout/sprout.jwt"))
			jety.SetDefault("sproutgatewayjwtfile", filepath.Join(systemConfigRoot, "pki/sprout/gateway.jwt"))
			jety.SetDefault("sprouttenantx25519pubfile", filepath.Join(systemConfigRoot, "pki/sprout/tenant-x25519.pub"))
			jety.SetDefault("sproutbusurlsfile", filepath.Join(systemConfigRoot, "pki/sprout/bus-urls.json"))
			jety.SetDefault("sproutboxprivfile", filepath.Join(systemConfigRoot, "pki/sprout/sprout-x25519.key"))
			jety.SetDefault("sproutboxpubfile", filepath.Join(systemConfigRoot, "pki/sprout/sprout-x25519.pub"))
			// Farmer's default; a sprout schedules gateway JWT refreshes
			// from each token's own iat/exp and only falls back to this
			// when a token doesn't carry them.
			jety.SetDefault("gatewayjwtttl", 24*time.Hour)
			jety.SetDefault("gatewayjwtrefreshmargin", DefaultGatewayJWTRefreshMargin)
			jety.SetDefault("stagedrecipemaxage", DefaultStagedRecipeMaxAge)
			jety.SetDefault("sprouthandledjobsfile", "/var/lib/imas/sprout/handled-jobs")
			jety.SetDefault("rootca_retry_delay", 5*time.Second)
			jety.SetDefault("nkey_retry_delay", 5*time.Second)
			jety.SetDefault("enroll_retry_delay", 5*time.Second)

			JobLogDir = jety.GetString("joblogdir")
			JobLogTTL = jety.GetDuration("joblogttl")
			GatewayJWTRefreshMargin = jety.GetDuration("gatewayjwtrefreshmargin")
			StagedRecipeMaxAge = jety.GetDuration("stagedrecipemaxage")
			SproutHandledJobsFile = jety.GetString("sprouthandledjobsfile")
			SproutRootCATOFU = jety.GetBool("sproutrootcatofu")
			BusURLs = stringList(jety.Get("busurls"))

			// The sprout config file can hold the join token. os.Create
			// (above, and in jety.WriteConfig) leaves a new file 0644
			// under the usual umask, and WriteConfig keeps an existing
			// file's mode, so tighten it here, before anything is written
			// to it, on every start: that also fixes files created by
			// earlier versions.
			cfgFile := filepath.Join(systemConfigRoot, "sprout")
			if err := os.Chmod(cfgFile, sproutConfigMode); err != nil && !os.IsNotExist(err) {
				log.Errorf("failed to restrict %s to mode %o: %v", cfgFile, sproutConfigMode, err)
			}
		}
		jety.WriteConfig()
	})
	logLevel := jety.GetString("loglevel")
	switch logLevel {
	case "debug":
		LogLevel = log.LDebug
	case "info":
		LogLevel = log.LInfo
	case "notice":
		LogLevel = log.LNotice
	case "warn":
		LogLevel = log.LWarn
	case "error":
		LogLevel = log.LError
	case "panic":
		LogLevel = log.LPanic
	case "fatal":
		LogLevel = log.LFatal
	default:
		LogLevel = log.LNotice
	}
	APIIdleTimeout = jety.GetDuration("apiidletimeout")
	APIReadTimeout = jety.GetDuration("apireadtimeout")
	APIWriteTimeout = jety.GetDuration("apiwritetimeout")
	AuditLevel = jety.GetString("auditlevel")
	AuditLogDir = jety.GetString("auditlogdir")
	CacheDir = jety.GetString("cachedir")
	CertFile = jety.GetString("certfile")
	CertHosts = jety.GetStringSlice("certhosts")
	CohortRefreshInterval = jety.GetDuration("cohortrefreshinterval")
	CertificateValidTime = jety.GetDuration("certificatevalidtime")
	ConfigRoot = jety.GetString("configroot")
	FarmerAPIPort = jety.GetString("farmerapiport")
	FarmerBusURL = jety.GetString("farmerinterface") + ":" + jety.GetString("farmerbusport")
	FarmerBusPort = jety.GetString("farmerbusport")
	FarmerWSPort = jety.GetString("farmerwsport")
	FarmerInterface = jety.GetString("farmerinterface")
	FarmerPKI = jety.GetString("farmerpki")
	FarmerURL = "https://" + jety.GetString("farmerinterface") + ":" + jety.GetString("farmerapiport")
	ImasRootCA = jety.GetString("imasrootca")
	KeyFile = jety.GetString("keyfile")
	NKeyFarmerPrivFile = jety.GetString("nkeyfarmerprivfile")
	NKeyFarmerPubFile = jety.GetString("nkeyfarmerpubfile")
	NKeySproutPrivFile = jety.GetString("nkeysproutprivfile")
	NKeySproutPubFile = jety.GetString("nkeysproutpubfile")
	FarmerOrganization = jety.GetString("farmerorganization")
	GatewayJWTTTL = jety.GetDuration("gatewayjwtttl")
	GatewayTransitKeyName = jety.GetString("gatewaytransitkeyname")
	BoxKeyGraceDuration = jety.GetDuration("boxkeygraceduration")
	RootCA = jety.GetString("rootca")
	RootCAPriv = jety.GetString("rootcapriv")
	SproutID = jety.GetString("sproutid")
	SproutPKI = jety.GetString("sproutpki")
	SproutRootCA = jety.GetString("sproutrootca")
	SproutFleetSigningJWKS = jety.GetString("sproutfleetsigningjwks")
	SproutUserJWTFile = jety.GetString("sproutuserjwtfile")
	SproutGatewayJWTFile = jety.GetString("sproutgatewayjwtfile")
	SproutTenantX25519PubFile = jety.GetString("sprouttenantx25519pubfile")
	SproutBusURLsFile = jety.GetString("sproutbusurlsfile")
	SproutBoxPrivFile = jety.GetString("sproutboxprivfile")
	SproutBoxPubFile = jety.GetString("sproutboxpubfile")
	JoinToken, JoinTokenSource = resolveJoinToken()
	RecipeDir = jety.GetString("recipedir")
	if RecipeDir == "" {
		RecipeDir = filepath.Join("/", "srv", "imas", "recipes", "prod")
	}
	PXCDSN = jety.GetString("pxcdsn")
	ValkeyAddrs = jety.GetString("valkeyaddrs")
	S3Endpoint = jety.GetString("s3endpoint")
	S3AccessKeyID = jety.GetString("s3accesskeyid")
	S3SecretAccessKey = jety.GetString("s3secretaccesskey")
	S3UseSSL = jety.GetBool("s3usessl")
	S3Bucket = jety.GetString("s3bucket")
	S3JobBucket = jety.GetString("s3jobbucket")
	SproutBusURLs = jety.GetStringSlice("sproutbusurls")
}

// stringList reads a config value that may be written as a YAML list or
// as a comma-separated string, trimming entries and dropping empty ones.
// Anything else (unset, a number, a map) is an empty list.
func stringList(v any) []string {
	var list []string
	switch v := v.(type) {
	case string:
		list = strings.Split(v, ",")
	case []string:
		list = v
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				list = append(list, s)
			}
		}
	}
	var out []string
	for _, s := range list {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// JoinTokenOrigin is where a sprout's join token came from.
type JoinTokenOrigin string

const (
	JoinTokenFromNone JoinTokenOrigin = ""
	JoinTokenFromFile JoinTokenOrigin = "config file"
	JoinTokenFromEnv  JoinTokenOrigin = "environment (" + EnvJoinToken + ")"
	JoinTokenFromFlag JoinTokenOrigin = "--join-token flag"
)

// sproutConfigMode is the sprout config file's mode: it can hold the join
// token, so only its owner (root) may read it.
const sproutConfigMode = 0o600

// SetJoinTokenFromFlag sets the join token from the sprout's
// --join-token flag, which wins over every other source. An empty value
// is ignored.
func SetJoinTokenFromFlag(tok string) {
	if tok = strings.TrimSpace(tok); tok != "" {
		JoinToken = tok
		JoinTokenSource = JoinTokenFromFlag
	}
}

// ClearJoinToken forgets the join token and deletes it from the sprout
// config file, if the file holds one, whatever source JoinToken itself
// came from. Call it only once enrollment has been fully persisted. It
// returns the source the in-use token came from when that source is one
// the sprout can't change itself (the environment or the command line),
// so the caller can tell the operator to remove it there; otherwise
// JoinTokenFromNone.
func ClearJoinToken() (JoinTokenOrigin, error) {
	src := JoinTokenSource
	JoinToken = ""
	JoinTokenSource = JoinTokenFromNone
	if strings.TrimSpace(jety.GetString("jointoken")) != "" {
		jety.Set("jointoken", "")
		if err := jety.WriteConfig(); err != nil {
			return JoinTokenFromNone, fmt.Errorf("removing the join token from %s: %w", jety.ConfigFileUsed(), err)
		}
	}
	if src == JoinTokenFromEnv || src == JoinTokenFromFlag {
		return src, nil
	}
	return JoinTokenFromNone, nil
}

// EnvJoinToken is the environment variable a sprout reads its join
// token from (see JoinToken).
const EnvJoinToken = "IMAS_JOIN_TOKEN"

// resolveJoinToken returns the join token and its source: from
// IMAS_JOIN_TOKEN if set, else from the config file's "jointoken" key. Read straight from the
// environment rather than jety.Set, which LoadConfig's WriteConfig would
// then persist to the config file. Surrounding whitespace is trimmed, so
// a token written to a file or variable with a trailing newline still
// works.
func resolveJoinToken() (string, JoinTokenOrigin) {
	if v, found := os.LookupEnv(EnvJoinToken); found && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v), JoinTokenFromEnv
	}
	if v := strings.TrimSpace(jety.GetString("jointoken")); v != "" {
		return v, JoinTokenFromFile
	}
	return "", JoinTokenFromNone
}

// BasePathValid checks that the configured recipe directory exists.
func BasePathValid() bool {
	info, err := os.Stat(RecipeDir)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func Init() string {
	return jety.GetString("init")
}

// StaticProps returns the "props.static" config section as a nested map.
// Returns nil if the section is not defined.
//
// Expected YAML structure:
//
//	props:
//	  static:
//	    sprout-id-1:
//	      key: value
//	    sprout-id-2:
//	      key: value
func StaticProps() map[string]interface{} {
	return jety.GetStringMap("props.static")
}

func SetSproutID(id string) {
	jety.Set("sproutid", id)
	jety.WriteConfig()
}
