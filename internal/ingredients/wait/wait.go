// Package wait implements imas's wait ingredient: poll a shell command until
// it succeeds (or, negated, until it fails) or a timeout elapses. It is an
// atomic ingredient that retries internally -- it does not sequence other
// ingredients, and gating a later step on a wait's outcome is done the same
// way as with any other step, via the recipe engine's requisites.
package wait

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

const pollMethod = "poll"

var (
	ErrWaitMethodUndefined = errors.New("wait method undefined")
	ErrWaitMissingCmd      = errors.New("wait requires a cmd")
	ErrWaitInvalidTimeout  = errors.New("wait timeout must be a valid duration")
	ErrWaitInvalidInterval = errors.New("wait interval must be a valid duration")
	ErrWaitTimedOut        = errors.New("wait timed out before the condition was met")
)

const (
	defaultTimeout  = 60 * time.Second
	defaultInterval = 2 * time.Second
)

var pollMethodProps = ingredients.MethodPropsSet{
	ingredients.MethodProps{Key: "cmd", Type: "string", IsReq: true, Description: "shell command to poll"},
	ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false, Description: "give up after this long, e.g. 60s (default 60s)"},
	ingredients.MethodProps{Key: "interval", Type: "string", IsReq: false, Description: "delay between attempts, e.g. 2s (default 2s)"},
	ingredients.MethodProps{Key: "negate", Type: "bool", IsReq: false, Description: "wait until the command fails, instead of succeeds"},
}

// Compile-time interface check.
var _ cook.RecipeCooker = Wait{}

type Wait struct {
	id     string
	method string
	params map[string]interface{}
}

func (w Wait) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	parsed := Wait{id: id, method: method, params: params}
	if err := parsed.validate(); err != nil {
		return nil, err
	}
	return parsed, nil
}

func (w Wait) validate() error {
	set, err := w.PropertiesForMethod(w.method)
	if err != nil {
		return err
	}
	propSet, err := ingredients.PropMapToPropSet(set)
	if err != nil {
		return err
	}
	for _, v := range propSet {
		if v.IsReq {
			if _, ok := w.params[v.Key]; !ok {
				return fmt.Errorf("missing required property %s", v.Key)
			}
		}
	}
	return nil
}

func (w Wait) durationParam(key string, def time.Duration, errWrap error) (time.Duration, error) {
	s, ok := w.params[key].(string)
	if !ok || s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, errors.Join(errWrap, err)
	}
	return d, nil
}

func (w Wait) poll(ctx context.Context, test bool) (cook.Result, error) {
	cmdStr, ok := w.params["cmd"].(string)
	if !ok || cmdStr == "" {
		return cook.Result{Succeeded: false, Failed: true}, ErrWaitMissingCmd
	}

	timeout, err := w.durationParam("timeout", defaultTimeout, ErrWaitInvalidTimeout)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true}, err
	}
	interval, err := w.durationParam("interval", defaultInterval, ErrWaitInvalidInterval)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true}, err
	}
	negate, _ := w.params["negate"].(bool)

	if test {
		mode := "succeeds"
		if negate {
			mode = "fails"
		}
		return cook.Result{
			Succeeded: true, Failed: false, Changed: false,
			Notes: []fmt.Stringer{cook.Snprintf("would poll `%s` (every %s, up to %s) until it %s", cmdStr, interval, timeout, mode)},
		}, nil
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	attempts := 0
	for {
		attempts++
		conditionMet, runErr := runsAsExpected(waitCtx, cmdStr, negate)
		if runErr == nil && conditionMet {
			return cook.Result{
				Succeeded: true, Failed: false, Changed: false,
				Notes: []fmt.Stringer{cook.Snprintf("condition met after %d attempt(s)", attempts)},
			}, nil
		}

		select {
		case <-waitCtx.Done():
			return cook.Result{
				Succeeded: false, Failed: true, Changed: false,
				Notes: []fmt.Stringer{cook.Snprintf("gave up after %d attempt(s)", attempts)},
			}, errors.Join(ErrWaitTimedOut, waitCtx.Err())
		case <-time.After(interval):
		}
	}
}

// shellFor is the executable and arguments that run cmdStr through a shell
// on goos: sh -c on Unix, and powershell.exe on Windows, which has no sh.
func shellFor(goos, cmdStr string) (string, []string) {
	if goos == "windows" {
		return "powershell.exe", []string{"-NoProfile", "-NonInteractive", "-Command", cmdStr}
	}
	return "sh", []string{"-c", cmdStr}
}

// runsAsExpected runs cmdStr once and reports whether its outcome matches
// what's being waited for (success, or failure when negate is set). Only a
// genuine failure to invoke the shell is returned as an error; a nonzero
// exit is a normal "not yet" result to keep polling on.
func runsAsExpected(ctx context.Context, cmdStr string, negate bool) (bool, error) {
	exe, args := shellFor(runtime.GOOS, cmdStr)
	command := exec.CommandContext(ctx, exe, args...)
	runErr := command.Run()
	succeeded := runErr == nil
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return false, runErr
		}
	}
	if negate {
		return !succeeded, nil
	}
	return succeeded, nil
}

func (w Wait) Test(ctx context.Context) (cook.Result, error) {
	switch w.method {
	case pollMethod:
		return w.poll(ctx, true)
	default:
		return cook.Result{Succeeded: false, Failed: true},
			errors.Join(ErrWaitMethodUndefined, fmt.Errorf("method %s undefined", w.method))
	}
}

func (w Wait) Apply(ctx context.Context) (cook.Result, error) {
	switch w.method {
	case pollMethod:
		return w.poll(ctx, false)
	default:
		return cook.Result{Succeeded: false, Failed: true},
			errors.Join(ErrWaitMethodUndefined, fmt.Errorf("method %s undefined", w.method))
	}
}

func (w Wait) PropertiesForMethod(method string) (map[string]string, error) {
	switch method {
	case pollMethod:
		return pollMethodProps.ToMap(), nil
	default:
		return nil, errors.Join(ErrWaitMethodUndefined, fmt.Errorf("method %s undefined", method))
	}
}

func (w Wait) Methods() (string, []string) {
	return "wait", []string{pollMethod}
}

func (w Wait) Properties() (map[string]interface{}, error) {
	m := map[string]interface{}{}
	b, err := json.Marshal(w.params)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(b, &m)
	return m, err
}

func init() {
	ingredients.RegisterAllMethods(Wait{})
}
