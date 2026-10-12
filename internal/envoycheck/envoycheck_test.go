package envoycheck

import (
	"strings"
	"testing"
)

func config(enrollRetry, refreshRetry, vhostRetry any) map[string]any {
	route := func(retry any) map[string]any {
		r := map[string]any{"cluster": "farmer_api"}
		if retry != nil {
			r["retry_policy"] = retry
		}
		return r
	}
	vh := map[string]any{"name": "imas_dmz", "routes": []any{
		map[string]any{"match": map[string]any{"prefix": "/v1/enroll"}, "route": route(enrollRetry)},
		map[string]any{"match": map[string]any{"path": "/v1/refresh"}, "route": route(refreshRetry)},
		map[string]any{"match": map[string]any{"prefix": "/"}, "route": route(map[string]any{"retry_on": "5xx"})},
	}}
	if vhostRetry != nil {
		vh["retry_policy"] = vhostRetry
	}
	return map[string]any{"static_resources": map[string]any{"listeners": []any{map[string]any{
		"filter_chains": []any{map[string]any{"filters": []any{map[string]any{"typed_config": map[string]any{
			"route_config": map[string]any{"virtual_hosts": []any{vh}},
		}}}}},
	}}}}
}

func TestBusyRetryProblems(t *testing.T) {
	ok := map[string]any{"retry_on": "connect-failure,refused-stream", "num_retries": 1}
	for _, c := range []struct {
		name string
		cfg  map[string]any
		want string
	}{
		{"no retry policy", config(nil, nil, nil), ""},
		{"pre-answer conditions only", config(ok, ok, nil), ""},
		{"5xx on enroll", config(map[string]any{"retry_on": "5xx"}, ok, nil), `route /v1/enroll: retry_on names "5xx"`},
		{"gateway-error on refresh", config(ok, map[string]any{"retry_on": "connect-failure, gateway-error"}, nil), `route /v1/refresh: retry_on names "gateway-error"`},
		{"retriable status codes", config(map[string]any{"retry_on": "retriable-status-codes", "retriable_status_codes": []any{503}}, ok, nil), "retriable_status_codes"},
		{"codes without the condition", config(map[string]any{"retry_on": "connect-failure", "retriable_status_codes": []any{503}}, ok, nil), "retriable_status_codes"},
		{"reset", config(map[string]any{"retry_on": "reset"}, ok, nil), `"reset"`},
		{"virtual host", config(ok, ok, map[string]any{"retry_on": "5xx"}), `virtual host imas_dmz: retry_on names "5xx"`},
		{"malformed", config("5xx", ok, nil), "retry_policy is string"},
		{"no routes", map[string]any{}, "no /v1/enroll route"},
	} {
		got := strings.Join(BusyRetryProblems(c.cfg), "\n")
		if c.want == "" && got != "" {
			t.Errorf("%s: problems %q, want none", c.name, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s: problems %q, want one containing %q", c.name, got, c.want)
		}
	}
}
