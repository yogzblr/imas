//go:build windows

package shell

// Windows sprouts keep refusing shell (owner decision 2026-10-04: ConPTY
// needs Windows Server 2019, and the supported floor is Server 2016). The
// refusal follows the same rules as a Unix sprout's, so it leaks nothing
// and can't be used for a downgrade: a sealed start is opened and
// answered with a sealed "unsupported"; a plaintext start on a sprout
// with box keys gets encryption-required; anything else gets the old
// "not supported" message.

import (
	"encoding/json"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/payloadbox"
)

// sproutSession is never created on Windows.
type sproutSession struct{}

func (*sproutSession) run()   {}
func (*sproutSession) abort() {}

func (sp *Sprout) spawn(*payloadbox.Message, *StartBody) (StartReply, *sproutSession) {
	return StartReply{Error: CodeUnsupported}, nil
}

func plaintextRefusal(ready bool) *nats.Msg {
	if ready {
		return refusal(payloadbox.ErrorCodeEncryptionRequired)
	}
	data, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: "interactive shell is not supported on Windows sprouts"})
	return &nats.Msg{Data: data}
}

// CloseAll does nothing: no sessions run on Windows.
func (sp *Sprout) CloseAll() {}
