package pki

// The platform key and the SaaS API box key: farmer's end of sealed
// SaaS API <-> farmer traffic (docs/design/imas-payload-encryption-design.md,
// "Sealing the control plane", Decision B, J.1). FLAG FOR SECURITY REVIEW.
//
// Custody: OpenBao KV v2, under the tenant box base path
// (IMAS_TENANTBOX_OPENBAO_KV_PATH, "<base>"), never a Kubernetes Secret
// farmer mounts, and never the bus:
//
//	<base>/platform          {pub, priv, origin[, severed]}  the platform keypair.
//	                         farmer reads it (its tenantbox role); nothing
//	                         else does. Its KV version history is its
//	                         rotation history, as for a tenant key.
//	<base>/saasapi-box       {pub, priv}  the SaaS API's box keypair. The
//	                         SaaS API reads it (through External Secrets
//	                         into a Secret only its pods mount); farmer's
//	                         policy doesn't reach it.
//	<base>/controlplane-pub  {platform_pub, saasapi_box_pub}  the public
//	                         halves each end pins: farmer reads
//	                         saasapi_box_pub, the SaaS API platform_pub.
//
// All three are written by `farmer ensure-controlplane-box-keys`, a Helm
// hook Job with an OpenBao role of its own (controlplanekeys.go). Farmer
// only reads: it never generates the platform key, so two replicas can't
// race to create it and nothing farmer runs can replace it.
//
// The tenant ID of every a2f/f2a message is payloadbox.PlatformTenantID
// and its principal payloadbox.PrincipalSaaSAPI. The tenant a request
// concerns is in its params, checked at the point of effect as today.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/yogzblr/imas/internal/openbao"
	"github.com/yogzblr/imas/internal/payloadbox"

	log "github.com/yogzblr/imas/internal/log"
)

// KV secrets under the tenant box base path (see the file comment).
const (
	platformBoxSecret      = "platform"
	saasapiBoxSecret       = "saasapi-box"
	controlPlanePubSecret  = "controlplane-pub"
	controlPlanePubField   = "platform_pub"
	controlPlaneSaaSField  = "saasapi_box_pub"
	controlPlaneOriginJob  = "controlplane-keygen"
	platformBoxRereadAfter = tenantBoxRereadAfter
)

// ErrPlatformBoxNotProvisioned means the platform key, or the SaaS API
// box public key farmer pins, isn't in OpenBao: the keygen Job hasn't run.
// Farmer seals nothing to, and opens nothing from, the SaaS API until it
// has.
var ErrPlatformBoxNotProvisioned = errors.New("pki: platform box key or SaaS API box public key not provisioned (run the control-plane keygen Job)")

// readFields reads one version of a KV v2 secret's data (version 0: the
// current one). found is false, with a nil error, for a version that
// doesn't exist or was deleted.
func (c *obKVClient) readFields(ctx context.Context, path string, version int) (data map[string]string, ver int, created time.Time, found bool, err error) {
	var query map[string][]string
	if version > 0 {
		query = map[string][]string{"version": {strconv.Itoa(version)}}
	}
	secret, err := c.ob.Read(ctx, c.mount+"/data/"+path, query)
	if openbao.IsNotFound(err) {
		return nil, 0, time.Time{}, false, nil
	}
	if err != nil {
		return nil, 0, time.Time{}, false, fmt.Errorf("%w: %w", ErrTenantBoxReadFailed, err)
	}
	var gr kvV2GetData
	if err := openbao.DecodeData(secret, &gr); err != nil {
		return nil, 0, time.Time{}, false, fmt.Errorf("%w: %w", ErrTenantBoxReadFailed, err)
	}
	if gr.Data == nil {
		return nil, 0, time.Time{}, false, nil
	}
	created, _ = time.Parse(time.RFC3339Nano, gr.Metadata.CreatedTime)
	ver = gr.Metadata.Version
	if ver == 0 {
		ver = version
	}
	return gr.Data, ver, created, true, nil
}

// writeFields writes data as a new version of path, check-and-set on cas
// (0: only if never written). written is false, with a nil error, when
// the check-and-set refused it.
func (c *obKVClient) writeFields(ctx context.Context, path string, data map[string]string, cas int) (written bool, err error) {
	_, err = c.ob.Put(ctx, c.mount+"/data/"+path, map[string]any{
		"options": map[string]any{"cas": cas},
		"data":    data,
	})
	switch openbao.StatusCode(err) {
	case 0:
		if err != nil {
			return false, fmt.Errorf("%w: %w", ErrTenantBoxWriteFailed, err)
		}
		return true, nil
	case 400, 409:
		return false, nil
	default:
		return false, fmt.Errorf("%w: %w", ErrTenantBoxWriteFailed, err)
	}
}

func (c *obKVClient) secretPath(name string) string { return c.path + "/" + name }

// platformBoxState is what farmer reads for the SaaS API boundary.
type platformBoxState struct {
	keys *tenantBoxKeySet
	// saasapiPubs is the SaaS API box public key farmer pins, current
	// first, then the one before it while a rotation's grace window is
	// open.
	saasapiPubs []*[32]byte
	loaded      time.Time
}

var (
	platformBoxMu    sync.Mutex
	platformBoxCache *platformBoxState
)

// InvalidatePlatformBoxKeys drops the cached platform state, so the next
// use re-reads OpenBao.
func InvalidatePlatformBoxKeys() {
	platformBoxMu.Lock()
	defer platformBoxMu.Unlock()
	platformBoxCache = nil
}

// readPlatformBoxState reads the platform keypair and the pinned SaaS API
// box public key(s).
func (c *obKVClient) readPlatformBoxState(ctx context.Context) (*platformBoxState, error) {
	keys, found, err := c.readKeySet(ctx, c.secretPath(platformBoxSecret))
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrPlatformBoxNotProvisioned
	}
	data, ver, created, found, err := c.readFields(ctx, c.secretPath(controlPlanePubSecret), 0)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrPlatformBoxNotProvisioned
	}
	current, err := decodePinnedBoxPub(data[controlPlaneSaaSField])
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrTenantBoxReadFailed, controlPlaneSaaSField, err)
	}
	if got := data[controlPlanePubField]; got != "" && got != encodeBoxPub(keys.current.pub) {
		// The SaaS API pins controlplane-pub's platform_pub: if it isn't
		// the platform key farmer holds, nothing farmer seals will open
		// there. Loud, not fatal: the keygen Job rewrites it.
		log.Errorf("pki: %s's %s is not the current platform key; re-run the control-plane keygen Job", controlPlanePubSecret, controlPlanePubField)
	}
	st := &platformBoxState{keys: keys, saasapiPubs: []*[32]byte{current}, loaded: time.Now()}
	if ver > 1 && !created.IsZero() && time.Since(created) < tenantBoxGrace() {
		prevData, _, _, found, err := c.readFields(ctx, c.secretPath(controlPlanePubSecret), ver-1)
		if err != nil {
			return nil, err
		}
		if found {
			if prev, err := decodePinnedBoxPub(prevData[controlPlaneSaaSField]); err == nil && *prev != *current {
				st.saasapiPubs = append(st.saasapiPubs, prev)
			}
		}
	}
	return st, nil
}

func encodeBoxPub(k *[32]byte) string { return base64.StdEncoding.EncodeToString(k[:]) }

func decodePinnedBoxPub(b64 string) (*[32]byte, error) {
	k, err := decodeBoxKeyHalf(b64)
	if err != nil {
		return nil, err
	}
	if err := payloadbox.CheckPublicKey(k); err != nil {
		return nil, err
	}
	return k, nil
}

// loadPlatformBoxState returns the platform state, from the cache while
// it's younger than tenantBoxCacheTTL, and a stale copy for up to
// tenantBoxStaleLimit while OpenBao can't be reached.
func loadPlatformBoxState() (*platformBoxState, error) {
	platformBoxMu.Lock()
	defer platformBoxMu.Unlock()
	if platformBoxCache != nil && time.Since(platformBoxCache.loaded) < tenantBoxCacheTTL {
		return platformBoxCache, nil
	}
	client, err := newTenantBoxClientFromEnv()
	if err != nil {
		return nil, err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := client.readPlatformBoxState(ctx)
	if err != nil {
		if platformBoxCache != nil && !errors.Is(err, ErrPlatformBoxNotProvisioned) &&
			time.Since(platformBoxCache.loaded) < tenantBoxStaleLimit {
			log.Warnf("pki: re-reading the platform box keys failed, still using the copy read %s ago: %v",
				time.Since(platformBoxCache.loaded).Round(time.Second), err)
			return platformBoxCache, nil
		}
		return nil, err
	}
	platformBoxCache = st
	return st, nil
}

// PlatformBoxKeys returns the platform keypairs farmer seals SaaS API
// traffic under and opens it with: the current one first and, inside a
// non-severing rotation's grace window, the previous one.
func PlatformBoxKeys() ([]TenantBoxKey, error) {
	st, err := loadPlatformBoxState()
	if err != nil {
		return nil, err
	}
	return graceKeys(st.keys), nil
}

// graceKeys is set's current key and, inside the grace window after a
// non-severing rotation, the previous one.
func graceKeys(set *tenantBoxKeySet) []TenantBoxKey {
	keys := []TenantBoxKey{{Pub: set.current.pub, Priv: set.current.priv, Version: set.current.version}}
	if len(set.previous) > 0 && !set.current.created.IsZero() && time.Since(set.current.created) < tenantBoxGrace() {
		p := set.previous[0]
		keys = append(keys, TenantBoxKey{Pub: p.pub, Priv: p.priv, Version: p.version})
	}
	return keys
}

// OpenFromSaaSAPI opens data, a Call the SaaS API sealed under purpose
// for method on subject, trying every platform key against every SaaS
// API box public key farmer pins. Every failure to open is
// payloadbox.ErrOpen; freshness and replay are the caller's
// (internal/natsapi's sealedapi.go). If it doesn't open and the cached
// keys are older than platformBoxRereadAfter, they are re-read once.
func OpenFromSaaSAPI(purpose, method, subject string, data []byte) (*payloadbox.Message, *payloadbox.CallBody, error) {
	want := payloadbox.CallExpect{
		Purpose: purpose, TenantID: payloadbox.PlatformTenantID, Principal: payloadbox.PrincipalSaaSAPI,
		Method: method, Subject: subject,
	}
	open := func() (*payloadbox.Message, *payloadbox.CallBody, error) {
		st, err := loadPlatformBoxState()
		if err != nil {
			return nil, nil, err
		}
		var candidates []payloadbox.KeyPair
		for _, pk := range graceKeys(st.keys) {
			for _, sp := range st.saasapiPubs {
				candidates = append(candidates, payloadbox.KeyPair{PeerPub: sp, Priv: pk.Priv})
			}
		}
		return payloadbox.OpenCall(data, candidates, want)
	}
	msg, body, err := open()
	if !errors.Is(err, payloadbox.ErrOpen) {
		return msg, body, err
	}
	platformBoxMu.Lock()
	stale := platformBoxCache != nil && time.Since(platformBoxCache.loaded) > platformBoxRereadAfter
	platformBoxMu.Unlock()
	if !stale {
		return nil, nil, err
	}
	InvalidatePlatformBoxKeys()
	return open()
}

// sealToSaaSAPIPairs is one key pair per platform key in use, all to the
// SaaS API's current box public key.
func sealToSaaSAPIPairs() ([]payloadbox.KeyPair, error) {
	st, err := loadPlatformBoxState()
	if err != nil {
		return nil, err
	}
	var pairs []payloadbox.KeyPair
	for _, pk := range graceKeys(st.keys) {
		pairs = append(pairs, payloadbox.KeyPair{PeerPub: st.saasapiPubs[0], Priv: pk.Priv})
	}
	return pairs, nil
}

// SealReplyToSaaSAPI seals r, farmer's reply to a SaaS API Call (r's
// tenant and principal are set here), to the SaaS API's current box key,
// one copy per platform key in use.
func SealReplyToSaaSAPI(r payloadbox.Reply) ([]byte, error) {
	pairs, err := sealToSaaSAPIPairs()
	if err != nil {
		return nil, err
	}
	r.TenantID, r.Principal = payloadbox.PlatformTenantID, payloadbox.PrincipalSaaSAPI
	return payloadbox.SealReply(r, pairs)
}

// SealResultToSaaSAPI seals c, an asynchronous result farmer publishes to
// the SaaS API (f2a.tenant.(de)provisioned on its job's subject), the
// same way. It returns the message ID.
func SealResultToSaaSAPI(c payloadbox.Call) ([]byte, string, error) {
	pairs, err := sealToSaaSAPIPairs()
	if err != nil {
		return nil, "", err
	}
	c.TenantID, c.Principal = payloadbox.PlatformTenantID, payloadbox.PrincipalSaaSAPI
	return payloadbox.SealCall(c, pairs)
}
