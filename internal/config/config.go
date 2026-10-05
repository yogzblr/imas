package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/taigrr/jety"
	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/natsretry"
)

const ImasExt = "imas"

var BuildInfo Version

var configLoaded sync.Once

// systemConfigRoot is the root directory for farmer/sprout config files.
// Defaults to defaultSystemConfigRoot(): "/etc/imas", or
// %ProgramData%\imas on Windows (paths_windows.go). Tests can override
// via setSystemConfigRoot.
var systemConfigRoot = defaultSystemConfigRoot()

// EnvJobReconcileWindow sets JobReconcileWindow on farmer when the config
// file doesn't (e.g. from the Helm chart; see deploy/farmer).
const EnvJobReconcileWindow = "IMAS_JOB_RECONCILE_WINDOW"

// Recipe template render limits on farmer (RecipeTemplateLimits), set by
// the Helm chart's farmer.recipes.templateLimits. Unset or empty keeps
// internal/cook's default.
const (
	EnvRecipeMaxSourceBytes     = "IMAS_RECIPE_MAX_SOURCE_BYTES"
	EnvRecipeMaxRenderedBytes   = "IMAS_RECIPE_MAX_RENDERED_BYTES"
	EnvRecipeMaxValueBytes      = "IMAS_RECIPE_MAX_VALUE_BYTES"
	EnvRecipeRenderTimeout      = "IMAS_RECIPE_RENDER_TIMEOUT"
	EnvRecipeMaxRangeIterations = "IMAS_RECIPE_MAX_RANGE_ITERATIONS"
)

// RecipeTemplateLimits are the limits farmer renders recipe templates
// under (internal/cook's "Bounded work"). A zero field keeps cook's
// default. cmd/farmer hands them to cook.SetRenderLimits, which checks
// their ranges and stops startup if one is out of range.
type RecipeTemplateLimits struct {
	MaxSourceBytes     int
	MaxRenderedBytes   int
	MaxValueBytes      int
	RenderTimeout      time.Duration
	MaxRangeIterations int
}

// Sprout setting defaults; see GatewayJWTRefreshMargin,
// StagedRecipeMaxAge, StagedRecipeClockSkew and SproutBoxKeyPrevGrace.
const (
	DefaultGatewayJWTRefreshMargin = 5 * time.Minute
	DefaultStagedRecipeMaxAge      = time.Hour
	DefaultSproutBoxKeyPrevGrace   = 15 * time.Minute

	// DefaultStagedRecipeClockSkew matches replayCacheClockMargin
	// (internal/pki), the margin the repo already allows for clock
	// differences between farmer replicas, which is what this tolerates.
	DefaultStagedRecipeClockSkew = time.Minute
	// MaxStagedRecipeClockSkew is the widest skew the repo accepts
	// anywhere (payloadbox.DefaultMaxSkew, pki.EnrollSigMaxSkew, saasapi's
	// maxRolloutClockSkew). Every second of tolerance is a second in which
	// an older job the sprout never ran can still be cooked after a newer
	// one it did.
	MaxStagedRecipeClockSkew = 5 * time.Minute
)

// stagedRecipeClockSkewFrom validates a "stagedrecipeclockskew" value:
// a Go duration string (or a time.Duration, the default) from 0 to
// MaxStagedRecipeClockSkew, or a bare 0. A bare number other than 0 has
// no unit, so it is refused rather than read as nanoseconds. On an error
// it returns DefaultStagedRecipeClockSkew.
func stagedRecipeClockSkewFrom(v any) (time.Duration, error) {
	var d time.Duration
	switch v := v.(type) {
	case nil:
		return DefaultStagedRecipeClockSkew, nil
	case time.Duration:
		d = v
	case string:
		parsed, err := time.ParseDuration(strings.TrimSpace(v))
		if err != nil {
			return DefaultStagedRecipeClockSkew, fmt.Errorf("stagedrecipeclockskew %q is not a duration", v)
		}
		d = parsed
	case int, int64, uint64, float64:
		if fmt.Sprint(v) != "0" {
			return DefaultStagedRecipeClockSkew, fmt.Errorf("stagedrecipeclockskew %v has no unit (write e.g. 30s)", v)
		}
	default:
		return DefaultStagedRecipeClockSkew, fmt.Errorf("stagedrecipeclockskew %v is not a duration", v)
	}
	if d < 0 || d > MaxStagedRecipeClockSkew {
		return DefaultStagedRecipeClockSkew, fmt.Errorf("stagedrecipeclockskew %v is outside 0 to %v", d, MaxStagedRecipeClockSkew)
	}
	return d, nil
}

// setSystemConfigRoot overrides the config root for testing.
func setSystemConfigRoot(root string) {
	systemConfigRoot = root
}

// resetSystemConfigRoot restores the default config root.
func resetSystemConfigRoot() {
	systemConfigRoot = defaultSystemConfigRoot()
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

	// FarmerBusURL is the bus address cmd/farmer, the imas CLI and
	// (as a last resort, see pki.ResolveSproutBusURLs) sprouts dial:
	// farmerinterface:farmerbusport, except that farmer and the imas CLI
	// read "farmerbusurl" (or the FARMERBUSURL environment variable)
	// first. Set it whenever farmerinterface isn't where the bus is
	// reachable — e.g. in Kubernetes, where core binds 0.0.0.0 and the
	// bus is a separate Service such as
	// "tls://imas-dmz-nats-bus.imas-dmz.svc.cluster.local:5406". It may
	// carry a scheme (nats://, tls://) or be a bare host:port. Sprouts
	// ignore it: they pin bus addresses with the validated "busurls"
	// instead (see BusURLs).
	FarmerBusURL  string
	FarmerBusPort string
	// FarmerBusTLSServerName ("farmerbustlsservername", or the
	// FARMERBUSTLSSERVERNAME environment variable; farmer and the imas
	// CLI only) is the name cmd/farmer and the imas CLI's bus client
	// (internal/api/client.NewNatsClient) verify the bus's TLS
	// certificate against when they dial FarmerBusURL. It is
	// deliberately separate from FarmerInterface,
	// which is a bind address (0.0.0.0 or a pod IP in Kubernetes) and so
	// never a name a certificate carries. Empty means "derive it from
	// FarmerBusURL": use BusTLSServerName for the effective value.
	FarmerBusTLSServerName string
	// FarmerWSPort is the port for nats-server's websocket listener —
	// what Envoy's jwt_authn-gated route proxies sprout wss:// connections
	// to, per docs/design/imas-envoy-enrollment-design.md. Distinct from
	// FarmerBusPort (the plain TCP NATS listener imas CLI/farmer-to-farmer
	// connections still use).
	FarmerWSPort string
	// BusMaxConnections ("busmaxconnections", farmer and farmerbus) is
	// the most client connections one bus node accepts, across its TCP
	// and websocket listeners (nats-server's max_connections). 0, the
	// default, keeps nats-server's own default of 65,536, which caps a
	// node well below the sprout counts docs/loadtest.md sizes for.
	// Negative values are refused (nats-server would then refuse every
	// client) and fall back to 0. Raising it needs the memory and file
	// descriptors to match: see deploy/helm/nats/README.md.
	BusMaxConnections int
	// FarmerInterface ("farmerinterface") is, on farmer and farmerbus,
	// the address their listeners bind: farmer's HTTPS API
	// (cmd/farmer's StartAPIServer) and the bus's NATS and websocket
	// listeners (pki.ConfigureNats). On sprouts and the imas CLI, which
	// bind nothing, it is the farmer host they reach. It is also the
	// default host of FarmerBusURL and FarmerURL. It is NOT the TLS
	// ServerName farmer or the imas CLI verifies the bus against; that is
	// FarmerBusTLSServerName.
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

	// SproutFleetSigningKeyring ("sproutfleetsigningkeyring", sprout only)
	// is the imas-fleet-signing public keyring the selfupdate ingredient
	// verifies every update manifest against (fleetsign.LoadKeyring,
	// design doc §2.5): a JSON object of key id to base64 Ed25519 public
	// key, shipped in the sprout package (packaging/etc/
	// fleet-signing-keys.json) and replaced by every package upgrade.
	// Default: fleet-signing-keys.json in the config root
	// (/etc/imas/fleet-signing-keys.json, %ProgramData%\imas\
	// fleet-signing-keys.json on Windows).
	SproutFleetSigningKeyring string

	// SproutUpdateRepoURL ("sproutupdaterepourl", sprout only) is the
	// https URL of the repository this sprout installs its own updates
	// from (requirement 20, design doc §1.8): the same per-OS repository
	// the Ansible role imas_sprout installs the sprout from, or a mirror.
	// An update command never carries a URL. What it points at depends on
	// SproutUpdateRepoFormat:
	//
	//   - apt: the apt repository URL of the sources.list line
	//     (https://packages.buildkite.com/<org>/imasdeb/any/);
	//   - rpm: the rpm repository's baseurl, "$basearch" filled in or left
	//     for the sprout to fill
	//     (https://packages.buildkite.com/<org>/imasrpm/rpm_any/rpm_any/$basearch);
	//   - nuget: the NuGet v3 feed's service index
	//     (https://packages.buildkite.com/<org>/imasnget/nuget/index.json);
	//   - flat: a directory serving each package file under its own name.
	//
	// Empty by default: the sprout refuses every self_update until it is
	// set.
	SproutUpdateRepoURL string

	// SproutUpdateRepoFormat ("sproutupdaterepoformat", sprout only) is how
	// the sprout finds the package file in SproutUpdateRepoURL: "apt",
	// "rpm", "nuget" or "flat". Empty (the default) means the format of
	// the sprout's own package: apt for a .deb, rpm for an .rpm, nuget for
	// an MSI.
	SproutUpdateRepoFormat string

	// SproutUpdateRepoDist ("sproutupdaterepodist", sprout only) is the
	// apt suite and component, "<suite> <component>" as in a sources.list
	// line. Empty (the default) means "any main", Buildkite's layout.
	SproutUpdateRepoDist string

	// SproutUpdateRepoPackageID ("sproutupdaterepopackageid", sprout
	// only) is the NuGet package carrying the MSI. Empty (the default)
	// means "imas.sprout.windows.msi", the installer package
	// packaging/windows/winget/build-winget-nupkg.sh builds.
	SproutUpdateRepoPackageID string

	// SproutUpdateRepoToken ("sproutupdaterepotoken", sprout only) is the
	// optional read token for a private SproutUpdateRepoURL, sent as HTTP
	// basic auth (user "buildkite", like the Ansible role's apt/yum/zypper
	// credentials) to the repository host only. A secret: it lives in the
	// sprout config file, which the sprout keeps at mode 0600. Empty by
	// default.
	SproutUpdateRepoToken string

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

	// BusProxyURL ("busproxyurl" in the sprout config file, sprout only)
	// is an outbound proxy the sprout dials every bus address through
	// (pki.LoadSproutBus): an http:// URL for an HTTP CONNECT proxy or a
	// socks5:// URL, with an explicit port and optionally the proxy's own
	// user:password, validated by pki.ValidateBusProxyURL. For installs
	// whose only way out is a proxy; the sprout's HTTP clients already
	// follow HTTP_PROXY/HTTPS_PROXY/NO_PROXY, which the bus does not.
	// Empty by default: dial directly.
	BusProxyURL string

	// BusReconnectBase and BusReconnectCap ("busreconnectbase" and
	// "busreconnectcap" in the sprout config file, sprout only) shape the
	// sprout's wait before each attempt to reach the bus, after losing it
	// and while its first connect keeps failing: a random wait between 0
	// and a ceiling that starts at BusReconnectBase and doubles with every
	// failed attempt up to BusReconnectCap, starting again from
	// BusReconnectBase once connected (internal/natsretry). The random
	// spread is what keeps a fleet from reconnecting in step after a bus
	// restart. Non-positive values fall back to natsretry.DefaultBase (2s)
	// and natsretry.DefaultCap (5m); a cap below the base is raised to it.
	BusReconnectBase time.Duration
	BusReconnectCap  time.Duration

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

	// StagedRecipeClockSkew ("stagedrecipeclockskew", sprout only) is how
	// much older than the newest job the sprout already handled a pulled
	// staged recipe's DispatchedAt may be and still be cooked (SEC.7d),
	// so a job stamped by a farmer replica whose clock runs slightly
	// behind isn't dropped. A Go duration from 0 (no tolerance) to
	// MaxStagedRecipeClockSkew; anything else is logged and replaced by
	// DefaultStagedRecipeClockSkew (stagedRecipeClockSkewFrom).
	StagedRecipeClockSkew = DefaultStagedRecipeClockSkew

	// SproutBoxKeyPrevGrace ("sproutboxkeyprevgrace", sprout only) is how
	// long a sprout keeps the X25519 private key a box key rotation
	// replaced, so farmer payloads sealed to it just before the switch
	// still open (internal/pki's sproutbox.go, "Box key rotation"). A
	// rotation triggered while it is kept is refused, so this is also the
	// shortest interval between two rotations. Non-positive values fall
	// back to DefaultSproutBoxKeyPrevGrace; values below
	// pki.MinSproutBoxKeyPrevGrace are raised to it. Longer keeps a
	// private key the rotation meant to retire on disk for longer.
	SproutBoxKeyPrevGrace time.Duration

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

	// RecipeLimits (farmer only) are the recipe template render limits,
	// from the IMAS_RECIPE_* variables above (no config-file keys). Each
	// must be a positive integer (bytes or iterations) or a positive Go
	// duration; anything else stops farmer at startup.
	RecipeLimits RecipeTemplateLimits

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
				f, err := os.Create(cfgFile)
				if err != nil {
					log.Fatal(err)
				}
				// Close it: on Windows an open handle blocks rewriting or
				// deleting the file.
				f.Close()
			}
		} else if err != nil {
			log.Printf("%T\n", err)
			panic(fmt.Errorf("fatal error config file: %w", err))
		}
		jety.SetDefault("loglevel", "info")
		jety.SetDefault("cachedir", defaultSproutCacheDir())
		jety.SetDefault("configroot", systemConfigRoot+string(filepath.Separator))
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
			BusMaxConnections = jety.GetInt("busmaxconnections")
			if BusMaxConnections < 0 {
				log.Errorf("busmaxconnections %d is negative, which would refuse every client; using the NATS server default", BusMaxConnections)
				BusMaxConnections = 0
			}
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
			limits, err := recipeTemplateLimitsFromEnv()
			if err != nil {
				log.Fatalf("%v", err)
			}
			RecipeLimits = limits
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
			jety.SetDefault("sproutpki", filepath.Join(systemConfigRoot, "pki/sprout")+string(filepath.Separator))
			jety.SetDefault("sproutrootca", filepath.Join(systemConfigRoot, "pki/sprout/tls-rootca.pem"))
			jety.SetDefault("sproutrootcatofu", true)
			jety.SetDefault("sproutfleetsigningkeyring", filepath.Join(systemConfigRoot, "fleet-signing-keys.json"))
			jety.SetDefault("nkeysproutpubfile", filepath.Join(systemConfigRoot, "pki/sprout/sprout.nkey.pub"))
			jety.SetDefault("joblogdir", defaultSproutJobLogDir())
			jety.SetDefault("joblogttl", 30*24*time.Hour) // 30 days default
			jety.SetDefault("nkeysproutprivfile", filepath.Join(systemConfigRoot, "pki/sprout/sprout.nkey"))
			jety.SetDefault("cachedir", defaultSproutCacheDir())
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
			jety.SetDefault("stagedrecipeclockskew", DefaultStagedRecipeClockSkew)
			jety.SetDefault("sproutboxkeyprevgrace", DefaultSproutBoxKeyPrevGrace)
			jety.SetDefault("busreconnectbase", natsretry.DefaultBase)
			jety.SetDefault("busreconnectcap", natsretry.DefaultCap)
			jety.SetDefault("sprouthandledjobsfile", defaultSproutHandledJobsFile())
			jety.SetDefault("rootca_retry_delay", 5*time.Second)
			jety.SetDefault("nkey_retry_delay", 5*time.Second)
			jety.SetDefault("enroll_retry_delay", 5*time.Second)

			JobLogDir = jety.GetString("joblogdir")
			JobLogTTL = jety.GetDuration("joblogttl")
			GatewayJWTRefreshMargin = jety.GetDuration("gatewayjwtrefreshmargin")
			StagedRecipeMaxAge = jety.GetDuration("stagedrecipemaxage")
			skew, err := stagedRecipeClockSkewFrom(jety.Get("stagedrecipeclockskew"))
			if err != nil {
				log.Errorf("config: %v; using %v", err, DefaultStagedRecipeClockSkew)
			}
			StagedRecipeClockSkew = skew
			SproutBoxKeyPrevGrace = jety.GetDuration("sproutboxkeyprevgrace")
			SproutHandledJobsFile = jety.GetString("sprouthandledjobsfile")
			SproutRootCATOFU = jety.GetBool("sproutrootcatofu")
			BusURLs = stringList(jety.Get("busurls"))
			BusProxyURL = strings.TrimSpace(jety.GetString("busproxyurl"))
			BusReconnectBase = jety.GetDuration("busreconnectbase")
			BusReconnectCap = jety.GetDuration("busreconnectcap")
			SproutFleetSigningKeyring = jety.GetString("sproutfleetsigningkeyring")
			SproutUpdateRepoURL = strings.TrimSpace(jety.GetString("sproutupdaterepourl"))
			SproutUpdateRepoToken = strings.TrimSpace(jety.GetString("sproutupdaterepotoken"))
			SproutUpdateRepoFormat = strings.TrimSpace(jety.GetString("sproutupdaterepoformat"))
			SproutUpdateRepoDist = strings.TrimSpace(jety.GetString("sproutupdaterepodist"))
			SproutUpdateRepoPackageID = strings.TrimSpace(jety.GetString("sproutupdaterepopackageid"))

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
	FarmerBusURL = ""
	FarmerBusTLSServerName = ""
	// Farmer and the imas CLI read the bus settings; sprouts don't. A
	// sprout pins bus addresses with the validated "busurls", and its
	// legacy FarmerBusURL fallback (pki.ResolveSproutBusURLs) skips that
	// validation, so it must not be redirectable by these keys.
	if binary == string(BinaryFarmer) || binary == string(BinaryImas) {
		FarmerBusURL = strings.TrimSpace(jety.GetString("farmerbusurl"))
		FarmerBusTLSServerName = strings.TrimSpace(jety.GetString("farmerbustlsservername"))
	}
	if FarmerBusURL == "" {
		FarmerBusURL = jety.GetString("farmerinterface") + ":" + jety.GetString("farmerbusport")
	}
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

// BusTLSServerName returns the TLS ServerName to verify the bus's
// certificate against when dialing FarmerBusURL: FarmerBusTLSServerName
// if set, else the host of FarmerBusURL (the first one, if it lists
// several). An unspecified address there (0.0.0.0, ::) — farmerinterface
// used as a bind address on a single-host install, where the bus is on
// the same host — becomes "localhost", which farmer's default certhosts
// cover. In Kubernetes, set farmerbusurl to the bus Service's DNS name
// (and the bus certificate's SANs to cover it) rather than relying on
// that.
func BusTLSServerName() string {
	if FarmerBusTLSServerName != "" {
		return FarmerBusTLSServerName
	}
	return busURLHost(FarmerBusURL)
}

// busURLHost returns the host of the first address in a NATS server
// list (comma-separated, each "scheme://host:port" or bare "host:port"),
// with an unspecified address mapped to "localhost". It is "" when
// busURL has no host.
func busURLHost(busURL string) string {
	first, _, _ := strings.Cut(busURL, ",")
	first = strings.TrimSpace(first)
	var host string
	if strings.Contains(first, "://") {
		if u, err := url.Parse(first); err == nil {
			host = u.Hostname()
		}
	} else if h, _, err := net.SplitHostPort(first); err == nil {
		host = h
	} else {
		host = strings.Trim(first, "[]")
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return "localhost"
	}
	return host
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

// recipeTemplateLimitsFromEnv reads RecipeTemplateLimits from the
// IMAS_RECIPE_* variables. An unset or empty variable leaves its field
// zero (cook's default); a set one must be positive, and the error names
// it.
func recipeTemplateLimitsFromEnv() (RecipeTemplateLimits, error) {
	var l RecipeTemplateLimits
	for _, f := range []struct {
		env string
		dst *int
	}{
		{EnvRecipeMaxSourceBytes, &l.MaxSourceBytes},
		{EnvRecipeMaxRenderedBytes, &l.MaxRenderedBytes},
		{EnvRecipeMaxValueBytes, &l.MaxValueBytes},
		{EnvRecipeMaxRangeIterations, &l.MaxRangeIterations},
	} {
		v := os.Getenv(f.env)
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return RecipeTemplateLimits{}, fmt.Errorf("%s=%q: want a positive whole number", f.env, v)
		}
		*f.dst = n
	}
	if v := os.Getenv(EnvRecipeRenderTimeout); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return RecipeTemplateLimits{}, fmt.Errorf("%s=%q: want a positive duration such as 2s", EnvRecipeRenderTimeout, v)
		}
		l.RenderTimeout = d
	}
	return l, nil
}
