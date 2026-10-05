package apitypes

import (
	"encoding/json"
	"errors"
)

// The error fields of CmdRun and CmdCook travel as their message string,
// or null for no error. encoding/json would otherwise write a non-nil
// error interface as its exported fields (`{}` for most errors,
// `{"Op":"cmd.run","SproutID":"web-01"}` for a cook.ReenrollRequiredError),
// which drops the message and cannot be decoded back into an error, so the
// CLI reported the whole result as an invalid message. The same approach
// as cook.StepCompletion's Error.

// errLegacyWireError stands in for an error that an older imas encoded as
// a JSON object: the result still failed, but its message was lost.
var errLegacyWireError = errors.New("error (message not sent by an older imas version)")

// wireErrorMessage is err's message, or nil for no error.
func wireErrorMessage(err error) *string {
	if err == nil {
		return nil
	}
	m := err.Error()
	return &m
}

// decodeWireError is the inverse of wireErrorMessage. It also accepts what
// older versions wrote: an object (an error whose message was lost).
func decodeWireError(raw json.RawMessage) error {
	var msg *string
	if err := json.Unmarshal(raw, &msg); err != nil {
		// Not null or a string: the legacy object encoding (or something
		// else we can't read). The result still failed, so keep that.
		return errLegacyWireError
	}
	if msg == nil {
		return nil
	}
	return errors.New(*msg)
}

// cmdRunFields has CmdRun's fields but none of its methods, so
// (Un)MarshalJSON can delegate to encoding/json without recursing.
type cmdRunFields CmdRun

// MarshalJSON encodes Error as its message string, or null when Error is
// nil.
func (c CmdRun) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		cmdRunFields
		Error *string `json:"error"`
	}{cmdRunFields(c), wireErrorMessage(c.Error)})
}

// UnmarshalJSON is the inverse of MarshalJSON. It also accepts the object
// older versions wrote for a non-nil Error, as an error whose message was
// lost, so a reply from a not-yet-upgraded farmer or sprout still decodes.
func (c *CmdRun) UnmarshalJSON(b []byte) error {
	aux := struct {
		cmdRunFields
		Error json.RawMessage `json:"error"`
	}{cmdRunFields: cmdRunFields(*c)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*c = CmdRun(aux.cmdRunFields)
	if aux.Error == nil {
		// Key absent: leave Error as it was, like encoding/json does.
		return nil
	}
	c.Error = decodeWireError(aux.Error)
	return nil
}

// cmdCookFields has CmdCook's fields but none of its methods.
type cmdCookFields CmdCook

// MarshalJSON encodes each of Errors as its message string, or null.
func (c CmdCook) MarshalJSON() ([]byte, error) {
	var errs map[string]*string
	if c.Errors != nil {
		errs = make(map[string]*string, len(c.Errors))
		for k, err := range c.Errors {
			errs[k] = wireErrorMessage(err)
		}
	}
	return json.Marshal(struct {
		cmdCookFields
		Errors map[string]*string `json:"errors"`
	}{cmdCookFields(c), errs})
}

// UnmarshalJSON is the inverse of MarshalJSON, and accepts the object
// older versions wrote for an error, as CmdRun's does.
func (c *CmdCook) UnmarshalJSON(b []byte) error {
	aux := struct {
		cmdCookFields
		Errors map[string]json.RawMessage `json:"errors"`
	}{cmdCookFields: cmdCookFields(*c)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*c = CmdCook(aux.cmdCookFields)
	if aux.Errors == nil {
		// Key absent or null: leave Errors as it was.
		return nil
	}
	c.Errors = make(map[string]error, len(aux.Errors))
	for k, raw := range aux.Errors {
		c.Errors[k] = decodeWireError(raw)
	}
	return nil
}
