package cron

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

var ErrCronMethodUndefined = errors.New("cron method undefined")

// Compile-time interface check.
var _ cook.RecipeCooker = Cron{}

// Cron manages a single per-user crontab entry, identified by name (used
// as the default identifier tag) so repeated applies are idempotent even
// if the schedule or command later changes.
type Cron struct {
	id     string
	method string
	params map[string]interface{}
}

func (c Cron) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	parsed := Cron{
		id: id, method: method,
		params: params,
	}
	if err := parsed.validate(); err != nil {
		return nil, err
	}
	return parsed, nil
}

func (c Cron) validate() error {
	set, err := c.PropertiesForMethod(c.method)
	if err != nil {
		return err
	}
	propSet, err := ingredients.PropMapToPropSet(set)
	if err != nil {
		return err
	}
	for _, v := range propSet {
		if v.IsReq {
			if v.Key == "name" {
				name, ok := c.params[v.Key].(string)
				if !ok || name == "" {
					return ingredients.ErrMissingName
				}
			} else if _, ok := c.params[v.Key]; !ok {
				return fmt.Errorf("missing required property %s", v.Key)
			}
		}
	}
	return nil
}

func (c Cron) Test(ctx context.Context) (cook.Result, error) {
	switch c.method {
	case "present":
		return c.present(ctx, true)
	case "absent":
		return c.absent(ctx, true)
	default:
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil},
			errors.Join(ErrCronMethodUndefined, fmt.Errorf("method %s undefined", c.method))
	}
}

func (c Cron) Apply(ctx context.Context) (cook.Result, error) {
	switch c.method {
	case "present":
		return c.present(ctx, false)
	case "absent":
		return c.absent(ctx, false)
	default:
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil},
			errors.Join(ErrCronMethodUndefined, fmt.Errorf("method %s undefined", c.method))
	}
}

func (c Cron) PropertiesForMethod(method string) (map[string]string, error) {
	switch method {
	case "present":
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "identifier for this cron entry"},
			ingredients.MethodProps{Key: "command", Type: "string", IsReq: true, Description: "the command to run"},
			ingredients.MethodProps{Key: "user", Type: "string", IsReq: false, Description: "the user whose crontab to manage (default: current user)"},
			ingredients.MethodProps{Key: "identifier", Type: "string", IsReq: false, Description: "override the entry's tracking identifier (default: name)"},
			ingredients.MethodProps{Key: "minute", Type: "string", IsReq: false, Description: "cron minute field (default *)"},
			ingredients.MethodProps{Key: "hour", Type: "string", IsReq: false, Description: "cron hour field (default *)"},
			ingredients.MethodProps{Key: "dayofmonth", Type: "string", IsReq: false, Description: "cron day-of-month field (default *)"},
			ingredients.MethodProps{Key: "month", Type: "string", IsReq: false, Description: "cron month field (default *)"},
			ingredients.MethodProps{Key: "dayofweek", Type: "string", IsReq: false, Description: "cron day-of-week field (default *)"},
		}.ToMap(), nil
	case "absent":
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "identifier for the cron entry to remove"},
			ingredients.MethodProps{Key: "command", Type: "string", IsReq: false, Description: "fallback match by exact command if no entry carries this identifier"},
			ingredients.MethodProps{Key: "user", Type: "string", IsReq: false, Description: "the user whose crontab to manage (default: current user)"},
			ingredients.MethodProps{Key: "identifier", Type: "string", IsReq: false, Description: "override the entry's tracking identifier (default: name)"},
		}.ToMap(), nil
	default:
		return nil, errors.Join(ErrCronMethodUndefined, fmt.Errorf("method %s undefined", method))
	}
}

func (c Cron) Methods() (string, []string) {
	return "cron", []string{"present", "absent"}
}

func (c Cron) Properties() (map[string]interface{}, error) {
	out := map[string]interface{}{}
	b, err := json.Marshal(c.params)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(b, &out)
	return out, err
}

// identifierFor returns the configured identifier, defaulting to name.
func (c Cron) identifierFor() string {
	id := stringParam(c.params, "identifier")
	if id != "" {
		return id
	}
	return stringParam(c.params, "name")
}

func init() {
	ingredients.RegisterAllMethods(Cron{})
}
