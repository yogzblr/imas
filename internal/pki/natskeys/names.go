package natskeys

// Transit key names for the NATS trust chain (P21 slice 1 brief §3.1).
// Names are flat (no "/"): whether Transit accepts slashes in a key name
// is unverified (TestOpenBaoSlashKeyNames records the answer), and every
// name is built here so switching to the design's "nats/..." names is a
// change to this file and the policies only.
const (
	operatorKey        = "nats-operator"
	operatorSigningKey = "nats-operator-signing"
	sysAccountKey      = "nats-sys-account"
	tenantSigningKey   = "nats-tsign-"
	tenantAccountKey   = "nats-tacct-"
)

// OperatorKey is the operator identity key (prefix O). Only the bootstrap
// Job signs with it (design D3).
func OperatorKey() string { return operatorKey }

// OperatorSigningKey is the operator signing key (prefix O), listed in
// the operator JWT; it signs every account JWT.
func OperatorSigningKey() string { return operatorSigningKey }

// SysAccountKey is the SYS account key (prefix A).
func SysAccountKey() string { return sysAccountKey }

// TenantSigningKey is tenantID's account signing key (prefix A); it signs
// the tenant's user JWTs.
func TenantSigningKey(tenantID string) string { return tenantSigningKey + tenantID }

// TenantAccountKey is tenantID's account identity key (prefix A). Its
// public key is the account's subject; nothing signs with it.
func TenantAccountKey(tenantID string) string { return tenantAccountKey + tenantID }
