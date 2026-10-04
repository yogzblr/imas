package cmd

// imas auth keygen and imas auth rotate-key: the CLI box key
// (docs/design/imas-payload-encryption-design.md, "Sealing the control
// plane", Decision A, J.1). FLAG FOR SECURITY REVIEW.
//
// The CLI box key is an X25519 key whose private half never leaves this
// host (cliboxprivfile, mode 0600). Once farmer accepts only sealed
// requests (J.3), every imas.api.* request is sealed with it to the
// tenant's box key the CLI pins (tenantboxpub, with tenantid), and it is
// what proves to farmer which user sent a request. The NKey keeps
// authenticating the bus connection only: the bus chooses the nonce the
// NKey signs, so a signature from it proves nothing to farmer.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/spf13/cobra"

	"github.com/yogzblr/imas/internal/api/client"
	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

var authKeygenForce bool

func init() {
	authKeygenCmd.Flags().BoolVar(&authKeygenForce, "force", false,
		"replace an existing CLI box key (you then need an admin to register the new one)")
	authCmd.AddCommand(authKeygenCmd)
	authCmd.AddCommand(authRotateKeyCmd)
}

// keygenResult is imas auth keygen's output.
type keygenResult struct {
	Path        string `json:"path"`
	User        string `json:"user,omitempty"`
	BoxPub      string `json:"box_pub"`
	Fingerprint string `json:"fingerprint"`
	Error       string `json:"error,omitempty"`
}

var authKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Create this CLI's box key for sealed requests to farmer",
	Long: `Creates the CLI box key: an X25519 key pair whose private half stays in
cliboxprivfile (mode 0600, default ~/.config/imas/cli-box.key) and is
never sent anywhere. Prints the public half and its fingerprint, which an
admin registers for your user in your tenant.

Refuses to replace an existing key unless --force: the registered key is
what farmer checks, so replacing it locks you out until an admin
registers the new one. To change a registered key, use rotate-key.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		res := keygenResult{Path: pki.CLIBoxPrivFile()}
		pub, err := pki.GenerateCLIBoxKey(res.Path, authKeygenForce)
		if err == nil {
			res.BoxPub = pub
			res.Fingerprint = boxFingerprint(pub)
			res.User, _ = auth.GetPubkey()
		}
		printAuthBoxResult(res, err, func() {
			fmt.Printf("CLI box key written to %s\n", res.Path)
			if res.User != "" {
				fmt.Printf("User:        %s\n", res.User)
			}
			fmt.Printf("Box key:     %s\nFingerprint: %s\n", res.BoxPub, res.Fingerprint)
			fmt.Println("\nAsk an admin to register this box key for your user in your tenant.")
		})
	},
}

// rotateKeyResult is imas auth rotate-key's output.
type rotateKeyResult struct {
	BoxPub      string `json:"box_pub,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Error       string `json:"error,omitempty"`
}

// rotateKeyTimeout bounds the wait for farmer's answer.
var rotateKeyTimeout = 30 * time.Second

var authRotateKeyCmd = &cobra.Command{
	Use:   "rotate-key",
	Short: "Replace this CLI's registered box key with a new one",
	Long: `Generates a new CLI box key and sends its public half to farmer, sealed
under the current key, so only the holder of the current key can rotate
it. The new key is kept pending (<cliboxprivfile>.next) until farmer's
sealed reply opens under it, which proves farmer recorded it; only then
does it replace the current key, whose private half is destroyed. If the
request is lost or refused, the CLI stays on its current key, and the next
rotate-key resubmits the same pending key. Farmer keeps accepting the old
key for 15 minutes.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		if err := ensureNats(); err != nil {
			printAuthBoxResult(rotateKeyResult{}, err, nil)
			return
		}
		pub, err := rotateCLIBoxKey(client.NatsConn, rotateKeyTimeout)
		res := rotateKeyResult{}
		if err == nil {
			res.BoxPub, res.Fingerprint = pub, boxFingerprint(pub)
		}
		printAuthBoxResult(res, err, func() {
			fmt.Printf("CLI box key rotated.\nBox key:     %s\nFingerprint: %s\n", res.BoxPub, res.Fingerprint)
		})
	},
}

// errSealedNotServed: nothing on the bus answered the rotation.
var errSealedNotServed = errors.New("no farmer answered the rotation; the new key stays pending and the next rotate-key resubmits it")

// rotateCLIBoxKey runs one rotation round trip over nc and returns the
// new key. It never promotes a key on anything but a sealed reply that
// opens under that key.
func rotateCLIBoxKey(nc *nats.Conn, timeout time.Duration) (string, error) {
	if nc == nil {
		return "", errors.New("NATS connection not established")
	}
	data, id, userID, newPub, err := pki.BeginCLIBoxKeyRotation()
	if err != nil {
		return "", err
	}
	msg := nats.NewMsg(pki.CLIAPISubjectPrefix + pki.MethodAuthRotateKey)
	msg.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	msg.Header.Set(payloadbox.PrincipalHeader, userID)
	msg.Data = data
	resp, err := nc.RequestMsg(msg, timeout)
	if errors.Is(err, nats.ErrNoResponders) {
		return "", errSealedNotServed
	}
	if err != nil {
		return "", fmt.Errorf("sending the rotation: %w", err)
	}
	if code := resp.Header.Get(payloadbox.ErrorHeader); code != "" {
		return "", fmt.Errorf("farmer refused the rotation (%s); still on the current key", code)
	}
	if resp.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		return "", errors.New("farmer's answer wasn't sealed; refusing it, still on the current key")
	}
	body, err := pki.CLIOpenReply(pki.MethodAuthRotateKey, id, resp.Data)
	if err != nil {
		return "", fmt.Errorf("farmer's answer didn't open: %w; still on the current key", err)
	}
	if body.Error != "" {
		return "", fmt.Errorf("farmer refused the rotation: %s; still on the current key", body.Error)
	}
	if cur, err := pki.CLIBoxPub(); err != nil || cur != newPub {
		return "", errors.New("farmer's answer didn't confirm the new key; still on the current key")
	}
	return newPub, nil
}

func boxFingerprint(pub string) string {
	k, err := auth.DecodeCLIBoxPub(pub)
	if err != nil {
		return ""
	}
	return payloadbox.Fingerprint(k)
}

// printAuthBoxResult prints res as JSON (with err's text in its Error
// field) or, in text mode, calls text, and exits 1 on err.
func printAuthBoxResult(res any, err error, text func()) {
	switch outputMode {
	case "json":
		if err != nil {
			switch r := res.(type) {
			case keygenResult:
				r.Error = err.Error()
				res = r
			case rotateKeyResult:
				r.Error = err.Error()
				res = r
			}
		}
		jw, _ := json.Marshal(res)
		fmt.Println(string(jw))
	default:
		if err != nil {
			log.Println("Error: " + err.Error())
		} else if text != nil {
			text()
		}
	}
	if err != nil {
		os.Exit(1)
	}
}
