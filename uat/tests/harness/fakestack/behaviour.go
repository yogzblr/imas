package fakestack

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"
)

// --- recipes --------------------------------------------------------------------

var recipeNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}(\.[a-z0-9][a-z0-9_-]{0,63}){0,15}$`)

func validRecipeName(n string) bool {
	if !recipeNameRe.MatchString(n) {
		return false
	}
	first := strings.SplitN(n, ".", 2)[0]
	return first != "tenants" && first != "sprouts" && first != "jobs" && !strings.HasSuffix(n, "imas") && !strings.HasSuffix(n, "init")
}

type recipe struct {
	content string
	sha     string
	updated time.Time
}

func shaOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hasRole(claims map[string]any, role string) bool {
	ra, _ := claims["realm_access"].(map[string]any)
	roles, _ := ra["roles"].([]any)
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// recipes serves .../recipes and .../recipes/<name>. s.mu is held.
func (s *Stack) recipesRoute(w http.ResponseWriter, r *http.Request, claims map[string]any, tid string, rest []string) {
	write := r.Method == http.MethodPut || r.Method == http.MethodDelete
	if (write && !hasRole(claims, WriteRole)) || (!write && !hasRole(claims, ReadRole) && !hasRole(claims, WriteRole)) {
		writeErr(w, 403, "forbidden", "the caller lacks the role this route requires")
		return
	}
	if len(rest) == 1 {
		if r.Method != http.MethodGet {
			w.WriteHeader(405)
			return
		}
		var list []map[string]any
		for k, rc := range s.recipeStore {
			if strings.HasPrefix(k, tid+"/") {
				list = append(list, map[string]any{"name": strings.TrimPrefix(k, tid+"/"), "size": len(rc.content), "updated_at": rc.updated})
			}
		}
		writeJSON(w, 200, map[string]any{"recipes": list})
		return
	}
	name := rest[1]
	if !validRecipeName(name) {
		writeErr(w, 400, "invalid_recipe_name", "the name breaks a naming rule")
		return
	}
	key := tid + "/" + name
	cur, exists := s.recipeStore[key]
	ifMatch, ifNone := r.Header.Get("If-Match"), r.Header.Get("If-None-Match")
	switch r.Method {
	case http.MethodGet:
		if !exists {
			writeErr(w, 404, "recipe_not_found", "no such recipe")
			return
		}
		w.Header().Set("ETag", `"`+cur.sha+`"`)
		writeJSON(w, 200, map[string]any{"name": name, "sha256": cur.sha, "size": len(cur.content), "updated_at": cur.updated, "content": cur.content})
	case http.MethodDelete:
		if s.limited("recipes/"+tid, 10) {
			writeErr(w, 429, "rate_limited", "rate limited")
			return
		}
		if !exists {
			writeErr(w, 404, "recipe_not_found", "no such recipe")
			return
		}
		if ifMatch != "" && ifMatch != "*" && ifMatch != `"`+cur.sha+`"` {
			writeJSON(w, 412, map[string]any{"error": "precondition_failed", "message": "changed", "details": map[string]string{"current_sha256": cur.sha}})
			return
		}
		delete(s.recipeStore, key)
		w.WriteHeader(204)
	case http.MethodPut:
		if s.limited("recipes/"+tid, 10) {
			writeErr(w, 429, "rate_limited", "rate limited")
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "" {
			mt, _, _ := mime.ParseMediaType(ct)
			if mt != "application/yaml" && mt != "text/yaml" && mt != "text/plain" {
				writeErr(w, 415, "unsupported_media_type", "unsupported content type")
				return
			}
		}
		switch {
		case ifMatch == "" && ifNone == "":
			writeErr(w, 428, "precondition_required", "If-Match or If-None-Match is required")
			return
		case ifNone == "*" && exists:
			writeErr(w, 412, "precondition_failed", "it exists")
			return
		case ifMatch != "" && ifMatch != "*" && (!exists || ifMatch != `"`+cur.sha+`"`):
			details := map[string]string{}
			if exists {
				details["current_sha256"] = cur.sha
			}
			writeJSON(w, 412, map[string]any{"error": "precondition_failed", "message": "changed", "details": details})
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if code, msg := checkRecipe(string(body)); code != "" {
			writeErr(w, 422, code, msg)
			return
		}
		rc := recipe{content: string(body), sha: shaOf(string(body)), updated: time.Now().UTC()}
		s.recipeStore[key] = rc
		w.Header().Set("ETag", `"`+rc.sha+`"`)
		status := 201
		if exists {
			status = 200
		}
		writeJSON(w, status, map[string]any{"name": name, "sha256": rc.sha, "size": len(rc.content), "updated_at": rc.updated})
	default:
		w.WriteHeader(405)
	}
}

// checkRecipe is a small subset of saasapi's upload checks.
func checkRecipe(body string) (string, string) {
	if strings.TrimSpace(body) == "" {
		return "recipe_empty", "the recipe is empty"
	}
	for _, f := range []string{"env", "call", "html", "js", "template", "define", "block"} {
		if regexp.MustCompile(`\{\{-?\s*` + f + `\b`).MatchString(body) {
			return "recipe_template_forbidden", "forbidden template function " + f
		}
	}
	out, err := render(body, map[string]string{}, "")
	if err != nil {
		return "recipe_template_invalid", err.Error()
	}
	var m map[string]any
	if yaml.Unmarshal([]byte(out), &m) != nil || m == nil {
		return "recipe_yaml_invalid", "the rendered recipe isn't a YAML mapping"
	}
	return "", ""
}

func render(src string, props map[string]string, sproutID string) (string, error) {
	t, err := template.New("r").Funcs(template.FuncMap{
		"props":    func(k string) string { return props[k] },
		"hostname": func() string { return props["hostname"] },
		"sproutID": func() string { return sproutID },
		"upper":    strings.ToUpper,
	}).Parse(src)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, nil); err != nil {
		return "", err
	}
	return b.String(), nil
}

// cook renders a tenant's recipe for a host and applies its file.content
// steps. s.mu is held. It returns an item error code, or "".
func (s *Stack) cook(tid, name string, h *Host, test bool) string {
	rc, ok := s.recipeStore[tid+"/"+name]
	if !ok {
		return "job_failed"
	}
	goos := "linux"
	if h.OS == "windows" {
		goos = "windows"
	}
	out, err := render(rc.content, map[string]string{"os": goos, "hostname": h.VM}, h.SproutID)
	if err != nil {
		return "job_failed"
	}
	var doc struct {
		Steps map[string]map[string][]map[string]any `yaml:"steps"`
	}
	if yaml.Unmarshal([]byte(out), &doc) != nil {
		return "job_failed"
	}
	for _, step := range doc.Steps {
		for method, params := range step {
			if method != "file.content" {
				continue
			}
			var name, text string
			for _, p := range params {
				if v, ok := p["name"].(string); ok {
					name = v
				}
				if v, ok := p["text"].(string); ok {
					text = v
				}
			}
			if !strings.HasSuffix(text, "\n") {
				text += "\n"
			}
			if test || h.Files[name] == text {
				continue
			}
			h.Files[name] = text
			h.MTimes[name] = time.Now().Unix()
		}
	}
	return ""
}

// --- cmd.run --------------------------------------------------------------------

var psPathRe = regexp.MustCompile(`-Path '((?:[^']|'')*)'`)

// runCmd applies a cmd.run to a host, the way the harness's commands
// behave. s.mu is held. It returns the item status, exit code and error.
func (s *Stack) runCmd(h *Host, cmd, cwd, runAs string, args []string, timeout int) (string, int, string) {
	win := h.OS == "windows"
	join := func(dir, p string) string {
		if win {
			if strings.Contains(p, `:\`) {
				return p
			}
			return dir + `\` + p
		}
		if strings.HasPrefix(p, "/") {
			return p
		}
		return path.Join(dir, p)
	}
	if runAs != "" && win {
		return "failed", -1, "command_failed"
	}
	fields := strings.Fields(cmd)
	exe := fields[0]
	if args == nil {
		args = fields[1:]
	}
	full := strings.Join(args, " ")
	switch {
	case exe == "/bin/true" && win:
		return "failed", -1, "command_failed"
	case (exe == "sleep" || strings.Contains(full, "Start-Sleep")) && timeout > 0:
		return "failed", -1, "command_failed"
	case exe == "touch" && !win && len(args) == 1:
		p := join(cwd, args[0])
		h.Files[p] = ""
		h.MTimes[p] = time.Now().Unix()
		h.Owners[p] = "root"
		if runAs != "" {
			h.Owners[p] = runAs
		}
	case exe == "powershell.exe" && strings.Contains(full, "New-Item"):
		if m := psPathRe.FindStringSubmatch(full); m != nil {
			p := join(cwd, strings.ReplaceAll(m[1], "''", "'"))
			h.Files[p] = ""
			h.MTimes[p] = time.Now().Unix()
			h.Owners[p] = `NT AUTHORITY\SYSTEM`
		}
	}
	if code := exitCode(cmd, args); code != 0 {
		return "failed", code, "command_failed"
	}
	return "succeeded", 0, ""
}

// --- host scripts -------------------------------------------------------------------

var (
	multiRe  = regexp.MustCompile(`(?:\[ -e '((?:[^']|'"'"')*)' \]|Test-Path -LiteralPath '((?:[^']|'')*)'\) \{ Write-Output '__IMAS_UAT_EXISTS_)`)
	singleRe = regexp.MustCompile(`(?m)^(?:p=|\$p = )'((?:[^']|'"'"'|'')*)'`)
	tcpRe    = regexp.MustCompile(`/dev/tcp/([^/]+)/(\d+)|BeginConnect\('([^']+)', (\d+)`)
)

// hostScript answers the harness's host scripts for h. s.mu is held.
func (s *Stack) hostScript(h *Host, script string) string {
	var out strings.Builder
	switch {
	case strings.Contains(script, "__IMAS_UAT_GW_PAYLOAD"):
		c := fmt.Sprintf(`{"iss":"imas-gateway","sub":"UFAKE","tenant_id":%q,"sprout_id":%q,"exp":%d}`, TenantID(h.Tenant), h.SproutID, time.Now().Add(24*time.Hour).Unix())
		fmt.Fprintf(&out, "__IMAS_UAT_GW_PAYLOAD=%s\n", base64.RawURLEncoding.EncodeToString([]byte(c)))
	case strings.Contains(script, "__IMAS_UAT_PKG_VERSION"):
		svc := "active"
		if h.Stopped {
			svc = "inactive"
		}
		fmt.Fprintf(&out, "__IMAS_UAT_PKG_VERSION=%s\n__IMAS_UAT_SERVICE=%s\n__IMAS_UAT_FARMER=%s\n", h.Version, svc, s.host())
	case strings.Contains(script, "__IMAS_UAT_OLD_VERSION"):
		fmt.Fprintf(&out, "__IMAS_UAT_OLD_VERSION=%s\n__IMAS_UAT_AFTER_REMOVE=inactive\n__IMAS_UAT_NEW_VERSION=%s\n", h.Version, h.Version)
	case strings.Contains(script, "__IMAS_UAT_EXISTS_"):
		for i, m := range multiRe.FindAllStringSubmatch(script, -1) {
			p := m[1] + m[2]
			p = strings.NewReplacer(`'"'"'`, "'", "''", "'").Replace(p)
			_, ok := h.Files[p]
			fmt.Fprintf(&out, "__IMAS_UAT_EXISTS_%d=%s\n", i, yesNo(ok))
		}
	case strings.Contains(script, "__IMAS_UAT_EXISTS"):
		m := singleRe.FindStringSubmatch(script)
		if m == nil {
			break
		}
		p := strings.NewReplacer(`'"'"'`, "'", "''", "'").Replace(m[1])
		content, ok := h.Files[p]
		fmt.Fprintf(&out, "__IMAS_UAT_EXISTS=%s\n", yesNo(ok))
		if ok {
			fmt.Fprintf(&out, "__IMAS_UAT_CONTENT_B64=%s\n__IMAS_UAT_OWNER=%s\n__IMAS_UAT_MTIME=%d\n",
				base64.StdEncoding.EncodeToString([]byte(content)), h.Owners[p], h.MTimes[p])
		}
	case strings.Contains(script, "__IMAS_UAT_TCP_"):
		for i, m := range tcpRe.FindAllStringSubmatch(script, -1) {
			hostName, port := m[1]+m[3], m[2]+m[4]
			state := "closed"
			if hostName == s.host() && port == s.port() {
				state = "open"
			}
			fmt.Fprintf(&out, "__IMAS_UAT_TCP_%d=%s\n", i, state)
		}
	}
	return out.String()
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func (s *Stack) host() string {
	h := strings.TrimPrefix(s.Server.URL, "https://")
	return h[:strings.LastIndex(h, ":")]
}

func (s *Stack) port() string {
	h := s.Server.URL
	return h[strings.LastIndex(h, ":")+1:]
}
