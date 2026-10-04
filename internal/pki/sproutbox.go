package pki

// The sprout's end of sealed farmer<->sprout payloads
// (docs/design/imas-payload-encryption-design.md, workstream J), its
// half of authenticated tenant key rotation, and its half of box key
// rotation.
//
// FLAG FOR SECURITY REVIEW. Keys: the sprout's own X25519 private key
// (config.SproutBoxPrivFile, generated here by EnsureSproutBoxKey and
// never sent anywhere), up to two more during a box key rotation (see
// "Box key rotation" below), and the tenant public key it pinned at
// enrollment (config.SproutTenantX25519PubFile). All are read from disk
// on every use, not cached, so a re-pin (reconcileTenantKeyPin) or a key
// promotion takes effect on the very next message and no private key is
// held in memory between messages.
//
// The sprout also pins its tenant ID at enrollment (pinSproutTenant,
// next to the tenant key pin; security review 2026-10, H3). Every
// message it seals names that tenant, and it refuses every message that
// names another, even one that opens under its keys. The tenant pin never
// moves: a sprout belongs to one tenant for life.
//
// Replay protection survives a restart (M2): the replay guard's state,
// message IDs and timestamps only, is written atomically, 0600, to
// sproutReplayGuardFile before a message is acted on, and loaded back on
// the first message after a start. See sproutGuard.
//
// The pin only ever moves through reconcileTenantKeyPin: farmer's
// refresh (or enrollment) response names a different tenant key AND
// carries a continuity proof that opens under the currently pinned key,
// i.e. was sealed with the private key the sprout already trusts, and
// names exactly that new key. A different key without such a proof is
// still ErrTenantKeyMismatch, fatal as before.
//
// # Box key rotation
//
// Farmer-initiated only: the sprout rotates when it receives farmer's
// trigger (cmd/sprout's boxkey.rotate subscription calls
// BeginSproutBoxKeyRotation) and never on its own schedule or judgement.
// It submits the new public key sealed under its current key, which
// internal/natsapi's handleBoxKeySubmit requires, and farmer records it
// with pki.RotateSproutBoxKey.
//
// Farmer's SealToSprout seals to the sprout's active key only, and
// switches the moment it records the new one; the submission gets no
// reply. So the sprout can't just replace its key and submit: a
// submission lost on the bus (or refused, or never allowed through by the
// sprout's User JWT) would leave farmer sealing to a key the sprout has
// discarded and opening the sprout's replies under one it never heard of,
// and the next rotation's submission, sealed under that unknown key,
// would be refused too. The sprout would need re-enrolling.
//
// Instead a rotation moves through three key files, each 0600:
//
//   - current (config.SproutBoxPrivFile): the key the sprout knows farmer
//     has. Everything the sprout seals uses it (SproutSealForFarmer, and
//     the submission itself). Farmer opens it whether or not it has
//     recorded a newer key yet: its previous key stays valid there for
//     config.BoxKeyGraceDuration (ValidSproutBoxKeys).
//   - pending (sproutPendingBoxPrivFile): the key generated for the
//     rotation in progress and submitted, not yet known to have reached
//     farmer. A trigger while one exists resubmits it rather than
//     generating another, so a lost submission is retried by triggering
//     again and never leaves more than one unconfirmed key behind.
//   - previous (sproutPrevBoxPrivFile): the key current replaced, kept
//     SproutBoxKeyPrevGrace after the switch and then deleted.
//
// The switch happens when a farmer payload opens under the pending key
// (promoteSproutBoxKey). That is the confirmation the submission has no
// reply to give: farmer only ever seals to a sprout's active key, and
// only the holder of a tenant private key can seal anything that opens
// under the pinned tenant key, so a bus can neither fake it nor, short of
// dropping all of farmer's traffic, withhold it. Everything the sprout
// seals is a reply to a farmer request it has just opened (or the next
// submission), so the first request farmer seals to the new key promotes
// it before the reply to it is sealed.
//
// Opening tries current, then pending, then previous. Previous covers a
// payload farmer sealed to the old key just before recording the new
// one, arriving after one sealed to the new key has promoted it: without
// it, that payload would never open. The mirror of farmer's
// own active+grace model, with a much shorter window: see
// MinSproutBoxKeyPrevGrace.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/yogzblr/imas/internal/config"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// ErrSproutBoxNotReady means the sprout can't seal or open payloads: it
// has no box private key or no pinned tenant key, i.e. it enrolled
// before workstream J.
var ErrSproutBoxNotReady = errors.New("pki: sprout has no payload-encryption keys (box key or pinned tenant key)")

// ErrSproutBoxKeyRotationTooSoon means a rotation was triggered while the
// key the last one replaced is still inside SproutBoxKeyPrevGrace.
// Refused rather than overwriting that key, which a payload still in
// flight may need; the trigger can be sent again once the window closes.
var ErrSproutBoxKeyRotationTooSoon = errors.New("pki: the previous box key rotation's grace window is still open")

// MinSproutBoxKeyPrevGrace is the shortest time the sprout keeps the key
// a rotation replaced (config.SproutBoxKeyPrevGrace is raised to it).
// Everything opened with that key is a farmer payload sealed before
// farmer recorded the new key, and a payload is refused once its
// IssuedAt is payloadbox.DefaultMaxSkew old (sproutGuard). The one
// that promoted the new key was issued after farmer recorded it and at
// most DefaultMaxSkew ahead of the sprout's clock at promotion, so
// anything sealed to the old key is stale within 2*DefaultMaxSkew of
// promotion. (A continuity proof in a refresh response carries no
// IssuedAt, but is opened as soon as the HTTP response arrives.)
//
// The default, config.DefaultSproutBoxKeyPrevGrace, is one more
// DefaultMaxSkew, as margin for farmer replicas' clocks disagreeing with
// each other. Both are deliberately far shorter than farmer's
// config.BoxKeyGraceDuration: farmer's grace keeps a public key, which
// costs nothing, whereas this keeps a private key on disk, and deleting
// the old private key is what a rotation is for (a host compromise after
// this window can't decrypt traffic captured under it).
const MinSproutBoxKeyPrevGrace = 2 * payloadbox.DefaultMaxSkew

// SproutBoxKeyPrevGrace is how long the sprout keeps the key a rotation
// replaced: config.SproutBoxKeyPrevGrace, or its default if unset, and
// never less than MinSproutBoxKeyPrevGrace. Read on every use, and
// measured from when the key was replaced, so a change applies to a key
// already being kept.
func SproutBoxKeyPrevGrace() time.Duration {
	g := config.SproutBoxKeyPrevGrace
	if g <= 0 {
		g = config.DefaultSproutBoxKeyPrevGrace
	}
	return max(g, MinSproutBoxKeyPrevGrace)
}

// sproutPendingBoxPrivFile and sproutPrevBoxPrivFile sit next to
// config.SproutBoxPrivFile, so they share its directory's permissions.
func sproutPendingBoxPrivFile() string { return config.SproutBoxPrivFile + ".next" }
func sproutPrevBoxPrivFile() string    { return config.SproutBoxPrivFile + ".prev" }

// sproutBoxMu serialises every read and change of the box key files: a
// promotion rewrites two of them, and a reader that saw half of it could
// miss the key a payload was sealed to.
var sproutBoxMu sync.Mutex

// sproutBoxKeySubmitBody is the body of a box key submission
// (payloadbox.PurposeBoxKeySubmit). It must match internal/natsapi's
// boxKeySubmitRequest, which this package can't import;
// cmd/sprout's round-trip test runs one against the other.
type sproutBoxKeySubmitBody struct {
	Pub string `json:"pub"`
}

// ErrSproutTenantMismatch means farmer named a different tenant than the
// one this sprout pinned at enrollment. Nothing from that response is
// persisted; callers treat it as fatal, like ErrTenantKeyMismatch.
var ErrSproutTenantMismatch = errors.New("pki: farmer named a different tenant than the one this sprout was enrolled in; refusing it")

// ErrSproutTenantNotPinned means the sprout has payload-encryption keys
// but no pinned tenant ID. It can neither seal nor open anything: it
// fails closed, and re-enrolling fixes it.
var ErrSproutTenantNotPinned = errors.New("pki: sprout has no pinned tenant ID; re-enroll it")

// SproutTenantIDFile is where the sprout pins its tenant ID, next to
// config.SproutTenantX25519PubFile, the tenant key pin it goes with.
func SproutTenantIDFile() string {
	return filepath.Join(filepath.Dir(config.SproutTenantX25519PubFile), "tenant-id")
}

// pinSproutTenant pins tenantID as this sprout's tenant if none is pinned
// yet. It never replaces a pin: a different tenant is
// ErrSproutTenantMismatch.
func pinSproutTenant(tenantID string) error {
	if !IsValidTenantID(tenantID) {
		return fmt.Errorf("pki: farmer named an invalid tenant_id %q", tenantID)
	}
	err := writeFileOnce(SproutTenantIDFile(), []byte(tenantID), 0o644)
	if err == nil {
		return nil
	}
	if !os.IsExist(err) {
		return fmt.Errorf("pki: pinning tenant ID: %w", err)
	}
	return checkPinnedSproutTenant(tenantID)
}

// checkPinnedSproutTenant returns ErrSproutTenantMismatch if a tenant is
// pinned and tenantID isn't it. No pin yet is not an error.
func checkPinnedSproutTenant(tenantID string) error {
	pinned, err := SproutTenantID()
	if errors.Is(err, ErrSproutTenantNotPinned) {
		return nil
	}
	if err != nil {
		return err
	}
	if pinned != tenantID {
		return ErrSproutTenantMismatch
	}
	return nil
}

// SproutTenantID returns the tenant this sprout pinned at enrollment, or
// ErrSproutTenantNotPinned.
func SproutTenantID() (string, error) {
	b, err := os.ReadFile(SproutTenantIDFile())
	if os.IsNotExist(err) {
		return "", ErrSproutTenantNotPinned
	}
	if err != nil {
		return "", fmt.Errorf("pki: reading pinned tenant ID: %w", err)
	}
	id := strings.TrimSpace(string(b))
	if !IsValidTenantID(id) {
		return "", fmt.Errorf("pki: pinned tenant ID %q is malformed", id)
	}
	return id, nil
}

// sproutReplayGuardFile is where the sprout's replay guard is persisted,
// next to its box private key.
func sproutReplayGuardFile() string {
	return filepath.Join(filepath.Dir(config.SproutBoxPrivFile), "payload-replay.json")
}

var (
	sproutGuardMu   sync.Mutex
	sproutGuardPath string
	sproutGuardInst *payloadbox.ReplayGuard
	// sproutProcessStart is when this process started, for the
	// fallback floor of a replay guard file that can't be read.
	sproutProcessStart = time.Now()
)

// sproutGuard returns the replay guard for farmer->sprout messages,
// loading its persisted state the first time it is used in this process
// (or after the configured path changes, which only tests do). Every
// state it accepts a message in is written to sproutReplayGuardFile,
// atomically and 0600, before the message is acted on
// (payloadbox.ReplayGuard.Commit), so a restart forgets nothing.
//
// A missing file is a fresh guard: a sprout that has never accepted a
// sealed message. A file that exists but can't be read or parsed fails
// closed for one window: the guard refuses anything issued before this
// process started plus payloadbox.DefaultMaxSkew, which covers every
// message an earlier process could have accepted, at the cost of
// refusing farmer's messages for up to five minutes. The file is
// rewritten with the next accepted message.
func sproutGuard() *payloadbox.ReplayGuard {
	sproutGuardMu.Lock()
	defer sproutGuardMu.Unlock()
	path := sproutReplayGuardFile()
	if sproutGuardInst != nil && sproutGuardPath == path {
		return sproutGuardInst
	}
	g := payloadbox.NewReplayGuard()
	raw, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
	case err == nil:
		var st payloadbox.ReplayState
		if err = json.Unmarshal(raw, &st); err == nil {
			err = g.Restore(st)
		}
	}
	if err != nil && !os.IsNotExist(err) {
		log.Errorf("pki: the replay guard file %s can't be read (%v); refusing farmer messages issued before %s", path, err,
			sproutProcessStart.Add(payloadbox.DefaultMaxSkew).UTC().Format(time.RFC3339))
		_ = g.Restore(payloadbox.ReplayState{V: payloadbox.ReplayStateVersion,
			Floor: sproutProcessStart.Add(payloadbox.DefaultMaxSkew).Unix()})
	}
	g.Commit = func(st payloadbox.ReplayState) error {
		b, err := json.Marshal(st)
		if err != nil {
			return err
		}
		if err := writeFileAtomic(path, b, 0o600); err != nil {
			return fmt.Errorf("pki: persisting the replay guard: %w", err)
		}
		return nil
	}
	sproutGuardInst, sproutGuardPath = g, path
	return g
}

// ForgetSproutReplayGuard drops the in-memory replay guard, as a restart
// does: the next message loads it from disk again. For tests that
// simulate a sprout restart; nothing else needs it.
func ForgetSproutReplayGuard() {
	sproutGuardMu.Lock()
	defer sproutGuardMu.Unlock()
	sproutGuardInst, sproutGuardPath = nil, ""
}

// SproutBoxReady reports whether this sprout has both keys it needs to
// seal and open payloads. A sprout that does refuses plaintext on sealed
// boundaries.
func SproutBoxReady() bool {
	for _, p := range []string{config.SproutBoxPrivFile, config.SproutTenantX25519PubFile} {
		if p == "" {
			return false
		}
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}

// sproutBoxKeys is the pinned tenant ID and public key and every box
// private key the sprout holds. The caller wipes it when done.
type sproutBoxKeys struct {
	tenantID  string
	tenantPub *[32]byte
	current   *[32]byte
	// pending is nil unless a rotation is in progress.
	pending *[32]byte
	// previous is nil unless a rotation promoted a key within
	// SproutBoxKeyPrevGrace.
	previous *[32]byte
}

func (k *sproutBoxKeys) wipe() {
	for _, p := range []*[32]byte{k.current, k.pending, k.previous} {
		if p != nil {
			wipe(p[:])
		}
	}
}

// loadSproutBoxKeysLocked reads the sprout's keys, deleting the previous
// key first if its grace window has closed. The caller holds sproutBoxMu.
func loadSproutBoxKeysLocked() (*sproutBoxKeys, error) {
	if !SproutBoxReady() {
		return nil, ErrSproutBoxNotReady
	}
	pinned, err := os.ReadFile(config.SproutTenantX25519PubFile)
	if err != nil {
		return nil, fmt.Errorf("pki: reading pinned tenant X25519 public key: %w", err)
	}
	tenantPub, err := DecodeBoxPubKey(strings.TrimSpace(string(pinned)))
	if err != nil {
		return nil, fmt.Errorf("pki: pinned tenant X25519 public key: %w", err)
	}
	tenantID, err := SproutTenantID()
	if err != nil {
		return nil, err
	}
	k := &sproutBoxKeys{tenantID: tenantID, tenantPub: tenantPub}
	if k.current, err = readBoxPrivKeyFile(config.SproutBoxPrivFile, false); err != nil {
		return nil, err
	}
	if k.pending, err = readBoxPrivKeyFile(sproutPendingBoxPrivFile(), true); err != nil {
		k.wipe()
		return nil, err
	}
	prevPath := sproutPrevBoxPrivFile()
	// The file's mtime is when promoteSproutBoxKey wrote it.
	if fi, statErr := os.Stat(prevPath); statErr == nil && time.Since(fi.ModTime()) > SproutBoxKeyPrevGrace() {
		if err := os.Remove(prevPath); err != nil && !os.IsNotExist(err) {
			k.wipe()
			return nil, fmt.Errorf("pki: deleting the previous sprout X25519 key: %w", err)
		}
		log.Infof("pki: deleted the previous payload-encryption key, its grace window after rotation having closed")
	} else if k.previous, err = readBoxPrivKeyFile(prevPath, true); err != nil {
		k.wipe()
		return nil, err
	}
	return k, nil
}

func loadSproutBoxKeys() (*sproutBoxKeys, error) {
	sproutBoxMu.Lock()
	defer sproutBoxMu.Unlock()
	return loadSproutBoxKeysLocked()
}

// readBoxPrivKeyFile is readBoxPrivKey into a fixed-size key. If
// optional, a missing file is (nil, nil).
func readBoxPrivKeyFile(path string, optional bool) (*[32]byte, error) {
	raw, err := readBoxPrivKey(path)
	if err != nil {
		if optional && os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var k [32]byte
	copy(k[:], raw)
	wipe(raw)
	return &k, nil
}

// boxPubFromPriv derives priv's public key, standard base64, the form
// EnsureSproutBoxKey reports and farmer records.
func boxPubFromPriv(priv *[32]byte) (string, error) {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("pki: deriving sprout X25519 public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// openAsSprout opens data, a payload farmer sealed for sproutID under
// purpose, trying the sprout's current, pending and previous keys in that
// order. If it opened under the pending key, pendingPub is that key's
// public half, for promoteSproutBoxKey.
func openAsSprout(sproutID, purpose string, data []byte) (msg *payloadbox.Message, pendingPub string, err error) {
	keys, err := loadSproutBoxKeys()
	if err != nil {
		return nil, "", err
	}
	defer keys.wipe()
	want := payloadbox.Expect{Purpose: purpose, TenantID: keys.tenantID, SproutID: sproutID}
	for _, priv := range []*[32]byte{keys.current, keys.pending, keys.previous} {
		if priv == nil {
			continue
		}
		msg, err := payloadbox.Open(data, []payloadbox.KeyPair{{PeerPub: keys.tenantPub, Priv: priv}}, want)
		if err != nil {
			continue
		}
		if priv == keys.pending {
			if pendingPub, err = boxPubFromPriv(priv); err != nil {
				return nil, "", err
			}
		}
		return msg, pendingPub, nil
	}
	return nil, "", payloadbox.ErrOpen
}

// promoteSproutBoxKey makes the pending key whose public half is
// pendingPub current, and the current one previous, once a farmer
// payload has opened under it (see "Box key rotation" above). A no-op if
// that key is no longer pending, i.e. a concurrent open promoted it.
//
// Crash-safe: previous is written before pending is renamed over
// current, and a crash between the two leaves previous a copy of
// current with pending still in place, which the next payload sealed to
// pending promotes again.
func promoteSproutBoxKey(pendingPub string) error {
	sproutBoxMu.Lock()
	defer sproutBoxMu.Unlock()
	pendingPath := sproutPendingBoxPrivFile()
	pending, err := readBoxPrivKeyFile(pendingPath, true)
	if err != nil || pending == nil {
		return err
	}
	pub, err := boxPubFromPriv(pending)
	wipe(pending[:])
	if err != nil {
		return err
	}
	if pub != pendingPub {
		return nil
	}
	current, err := readBoxPrivKeyFile(config.SproutBoxPrivFile, false)
	if err != nil {
		return err
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(current[:]))
	wipe(current[:])
	err = writeFileAtomic(sproutPrevBoxPrivFile(), encoded, 0o600)
	wipe(encoded)
	if err != nil {
		return fmt.Errorf("pki: keeping the previous sprout X25519 key: %w", err)
	}
	if err := os.Rename(pendingPath, config.SproutBoxPrivFile); err != nil {
		return fmt.Errorf("pki: promoting the new sprout X25519 key: %w", err)
	}
	if config.SproutBoxPubFile != "" {
		if err := writeFileAtomic(config.SproutBoxPubFile, []byte(pub), 0o644); err != nil {
			// Informational only (EnsureSproutBoxKey rewrites it on the
			// next start); the private key file is what counts.
			log.Warnf("pki: writing sprout X25519 public key: %v", err)
		}
	}
	// Not the key itself: this line is shipped over the bus, and a
	// sprout's box public keys are for farmer alone (review 2026-10, H3).
	log.Noticef("pki: farmer is sealing to the new payload-encryption key; it is now current, and the one it replaced is kept for %s", SproutBoxKeyPrevGrace())
	return nil
}

// promoteAfterOpen promotes pendingPub, if set. A failure is logged, not
// returned: the payload itself opened, and the next one sealed to the
// pending key tries again.
func promoteAfterOpen(pendingPub string) {
	if pendingPub == "" {
		return
	}
	if err := promoteSproutBoxKey(pendingPub); err != nil {
		log.Errorf("pki: farmer is sealing to the new payload-encryption key, but promoting it failed: %v", err)
	}
}

// BeginSproutBoxKeyRotation handles farmer's rotate trigger for
// sproutID: it generates a fresh X25519 private key (crypto/rand, as
// EnsureSproutBoxKey does) and stores it as the pending key, or reuses
// the pending key if a rotation is already in progress, and returns the
// submission to publish on imas.sprouts.<sproutID>.boxkey.pub: its public
// half, sealed under the current key and the pinned tenant key
// (payloadbox.PurposeBoxKeySubmit), as internal/natsapi's
// handleBoxKeySubmit requires. pub is that public half.
//
// Nothing the sprout uses changes here; the pending key becomes current
// only once farmer seals to it (promoteSproutBoxKey), so a submission
// that never reaches farmer costs nothing. ErrSproutBoxKeyRotationTooSoon
// if the previous rotation's grace window is still open.
func BeginSproutBoxKeyRotation(sproutID string) (submission []byte, pub string, err error) {
	sproutBoxMu.Lock()
	defer sproutBoxMu.Unlock()
	keys, err := loadSproutBoxKeysLocked()
	if err != nil {
		return nil, "", err
	}
	defer keys.wipe()
	if keys.previous != nil {
		return nil, "", ErrSproutBoxKeyRotationTooSoon
	}
	if keys.pending == nil {
		var fresh [32]byte
		if _, err := rand.Read(fresh[:]); err != nil {
			return nil, "", fmt.Errorf("pki: generating sprout X25519 key: %w", err)
		}
		keys.pending = &fresh
		encoded := []byte(base64.StdEncoding.EncodeToString(fresh[:]))
		err := writeFileOnce(sproutPendingBoxPrivFile(), encoded, 0o600)
		wipe(encoded)
		if err != nil {
			return nil, "", fmt.Errorf("pki: writing the new sprout X25519 key: %w", err)
		}
	}
	if pub, err = boxPubFromPriv(keys.pending); err != nil {
		return nil, "", err
	}
	msg, err := payloadbox.NewMessage(payloadbox.PurposeBoxKeySubmit, keys.tenantID, sproutID, "", sproutBoxKeySubmitBody{Pub: pub})
	if err != nil {
		return nil, "", err
	}
	submission, err = payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: keys.tenantPub, Priv: keys.current}})
	if err != nil {
		return nil, "", err
	}
	return submission, pub, nil
}

// SproutOpenFromFarmer opens data, a payload farmer sealed for sproutID
// in the pinned tenant under purpose, and checks it is fresh and not a
// replay (payloadbox.ErrOpen, ErrStale, ErrReplayed; distinguishable in
// the sprout's own log only: a reply to farmer carries one generic code).
// The replay check is persisted before this returns (sproutGuard), so a
// message accepted before a restart is refused after it.
// Tries every key the sprout holds (openAsSprout); one that opens under
// the pending key promotes it, even if it then fails the freshness
// checks, since only farmer could have sealed it and farmer only seals to
// a key it has recorded.
func SproutOpenFromFarmer(sproutID, purpose string, data []byte) (*payloadbox.Message, error) {
	msg, pendingPub, err := openAsSprout(sproutID, purpose, data)
	if err != nil {
		return nil, err
	}
	promoteAfterOpen(pendingPub)
	if err := sproutGuard().Accept(msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// SproutSealForFarmer seals body from sproutID to farmer under purpose,
// answering the request whose message ID is replyTo (empty for a message
// that isn't a reply). Sealed under the pinned tenant key: farmer opens
// under its current key or, inside a rotation's grace window, the
// previous one, so a sprout that hasn't re-pinned yet still gets through.
// Always the sprout's current box key, never a pending one: farmer opens
// under the sprout's active key and any in grace, which the current key
// is whether or not farmer has recorded the pending one yet.
func SproutSealForFarmer(sproutID, purpose, replyTo string, body any) ([]byte, error) {
	keys, err := loadSproutBoxKeys()
	if err != nil {
		return nil, err
	}
	defer keys.wipe()
	msg, err := payloadbox.NewMessage(purpose, keys.tenantID, sproutID, replyTo, body)
	if err != nil {
		return nil, err
	}
	return payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: keys.tenantPub, Priv: keys.current}})
}

// reconcileTenantKeyPin checks pub, the tenant key in farmer's response
// to sproutID, against the pinned one. No pin yet, or the same key: nil.
// A different key: re-pins to pub if continuity (the response's
// tenant_x25519_continuity) proves the move, else ErrTenantKeyMismatch.
func reconcileTenantKeyPin(sproutID, pub string, continuity json.RawMessage) error {
	err := checkPinnedTenantKey(pub)
	if !errors.Is(err, ErrTenantKeyMismatch) {
		return err
	}
	if len(continuity) == 0 {
		return ErrTenantKeyMismatch
	}
	if err := verifyTenantKeyContinuity(sproutID, pub, continuity); err != nil {
		log.Errorf("pki: farmer's new tenant X25519 key came with a continuity proof that doesn't verify: %v", err)
		return ErrTenantKeyMismatch
	}
	if err := writeFileAtomic(config.SproutTenantX25519PubFile, []byte(pub), 0o644); err != nil {
		return fmt.Errorf("pki: re-pinning tenant X25519 public key: %w", err)
	}
	log.Noticef("pki: re-pinned the tenant X25519 public key after an authenticated tenant key rotation")
	return nil
}

// verifyTenantKeyContinuity opens proof under the pinned tenant key and
// this sprout's box keys and checks it names pub. Farmer seals the proof
// to the sprout's active box key, which may be the pending one; a proof
// that opens under it promotes it, as any farmer payload would.
func verifyTenantKeyContinuity(sproutID, pub string, proof json.RawMessage) error {
	msg, pendingPub, err := openAsSprout(sproutID, payloadbox.PurposeTenantKeyContinuity, proof)
	if err != nil {
		return err
	}
	promoteAfterOpen(pendingPub)
	var body tenantKeyContinuityBody
	if err := json.Unmarshal(msg.Body, &body); err != nil {
		return payloadbox.ErrOpen
	}
	if body.To != pub {
		return errors.New("proof names a different tenant key")
	}
	return nil
}

// enrollProofBody is the body of an enrollment proof of possession
// (payloadbox.PurposeEnrollProof): which NKey and box key it vouches for.
type enrollProofBody struct {
	NKeyPub   string `json:"nkey_pub"`
	SproutPub string `json:"sprout_pub"`
}

// sproutEnrollProof builds the sprout's proof that it holds the private
// half of sproutPub, its box public key, for the enrollment of nkeyPub
// as sproutID in tenantID: a payloadbox message under
// PurposeEnrollProof naming both keys, sealed with the box private key
// (config.SproutBoxPrivFile) to tenantPub, the tenant key farmer's first
// enrollment response named. See enroll.go's verifyEnrollProof for why
// this proves possession. Nothing is pinned or persisted here.
func sproutEnrollProof(tenantID, sproutID, tenantPub, nkeyPub, sproutPub string) (json.RawMessage, error) {
	tp, err := DecodeBoxPubKey(tenantPub)
	if err != nil {
		return nil, err
	}
	priv, err := readBoxPrivKeyFile(config.SproutBoxPrivFile, false)
	if err != nil {
		return nil, err
	}
	defer wipe(priv[:])
	if pub, err := boxPubFromPriv(priv); err != nil || pub != sproutPub {
		return nil, errors.New("pki: the box key on disk is not the one being enrolled")
	}
	msg, err := payloadbox.NewMessage(payloadbox.PurposeEnrollProof, tenantID, sproutID, "",
		enrollProofBody{NKeyPub: nkeyPub, SproutPub: sproutPub})
	if err != nil {
		return nil, err
	}
	return payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: tp, Priv: priv}})
}
