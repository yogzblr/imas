//go:build windows

// Package windnsclient wraps the core of Salt's win_dns_client module:
// setting an interface's static DNS server list via
// `netsh interface ip set/add dns`, the same CLI tool Salt itself shells
// out to. See G.9 in docs/design/imas-windows-parity-addendum.md.
package windnsclient

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_dns_client"

const methodConfigured = "configured"

var methodProps = map[string]ingredients.MethodPropsSet{
	methodConfigured: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "servers", Type: "[]string", IsReq: true},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
}

var ipRE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// Compile-time interface check.
var _ cook.RecipeCooker = Interface{}

// Interface manages the static DNS server list of a single network
// interface by name.
type Interface struct {
	id      string
	method  string
	name    string
	servers []string
	params  map[string]interface{}
}

func (i Interface) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	if _, ok := methodProps[method]; !ok {
		return nil, ingredients.ErrInvalidMethod
	}
	name, ok := winexec.StringParam(params, "name")
	if !ok || name == "" {
		return nil, ingredients.ErrMissingName
	}
	servers, ok := winexec.StringSliceParam(params, "servers")
	if !ok || len(servers) == 0 {
		return nil, fmt.Errorf("missing required property servers")
	}
	return Interface{id: id, method: method, name: name, servers: servers, params: params}, nil
}

func (i Interface) Methods() (string, []string) {
	return ingredientName, []string{methodConfigured}
}

func (i Interface) PropertiesForMethod(method string) (map[string]string, error) {
	p, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("method %s undefined", method)
	}
	return p.ToMap(), nil
}

func (i Interface) Properties() (map[string]interface{}, error) {
	return i.params, nil
}

// currentServers parses `netsh interface ip show dns name="<name>"`
// output for the configured DNS server IPs, in order.
func (i Interface) currentServers(ctx context.Context) ([]string, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(i.params, "timeout", ""))
	if err != nil {
		return nil, err
	}
	out, err := winexec.RunCLI(ctx, "netsh.exe", []string{
		"interface", "ip", "show", "dns", "name=" + i.name,
	}, timeout)
	if err != nil {
		return nil, err
	}
	var servers []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		if ip := ipRE.FindString(scanner.Text()); ip != "" {
			servers = append(servers, ip)
		}
	}
	return servers, nil
}

func sameServers(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for idx := range a {
		if a[idx] != b[idx] {
			return false
		}
	}
	return true
}

func (i Interface) Test(ctx context.Context) (cook.Result, error) {
	current, err := i.currentServers(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if sameServers(current, i.servers) {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s DNS servers already configured", i.name))}}, nil
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s DNS servers would be set to %v", i.name, i.servers))}}, nil
}

func (i Interface) Apply(ctx context.Context) (cook.Result, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(i.params, "timeout", ""))
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	current, err := i.currentServers(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if sameServers(current, i.servers) {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s DNS servers already configured", i.name))}}, nil
	}
	if _, err := winexec.RunCLI(ctx, "netsh.exe", []string{
		"interface", "ip", "set", "dns", "name=" + i.name, "static", i.servers[0], "primary",
	}, timeout); err != nil {
		return cook.Result{Failed: true}, err
	}
	for idx, server := range i.servers[1:] {
		if _, err := winexec.RunCLI(ctx, "netsh.exe", []string{
			"interface", "ip", "add", "dns", "name=" + i.name, server,
			fmt.Sprintf("index=%d", idx+2),
		}, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s DNS servers set to %v", i.name, i.servers))}}, nil
}

func init() {
	ingredients.RegisterAllMethods(Interface{})
}
