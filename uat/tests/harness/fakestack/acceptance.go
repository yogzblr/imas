package fakestack

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/retention"
)

// What uat/hub/core/acceptance.sh sees and changes inside a real hub, for
// the W1 cases, answered from the fake's memory: POST
// /_acceptance?verb=...&arg=...&arg=... with the verb's stdin as the body,
// the JSON line as the answer and X-Exit-Code 1 with the reason for a
// refusal (the fake acceptance.sh, material.go, forwards to it). Like the
// rest of the fake it proves the harness's plumbing, never the product.

// provJob is a saas.provisioning_jobs row.
type provJob struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Status  string `json:"status"`
	trigger string
	updated time.Time
}

// fakeProp is a farmer.props row.
type fakeProp struct {
	value  string
	expiry time.Time
}

// logLine is one line of farmer's or saasapi's log.
type logLine struct {
	at             time.Time
	workload, text string
}

func newUUID() string { return uuid.NewString() }

// hmacOK checks a token's HS256 signature under the fake's key.
func (s *Stack) hmacOK(signed, sig string) bool {
	m := hmac.New(sha256.New, s.signKey)
	m.Write([]byte(signed))
	b, err := base64.RawURLEncoding.DecodeString(sig)
	return err == nil && hmac.Equal(b, m.Sum(nil))
}

// addJob records a provisioning job; s.mu is held (or the stack is not
// serving yet).
func (s *Stack) addJob(tid, typ, status, trigger string) *provJob {
	j := &provJob{ID: "pj_" + base32ish(16), Type: typ, Status: status, trigger: trigger, updated: time.Now()}
	s.jobs[tid] = append(s.jobs[tid], j)
	return j
}

// setProps stores props for a tenant's sprout; s.mu is held.
func (s *Stack) setProps(tid, sid string, kv map[string]string, exp time.Time) {
	key := tid + "/" + sid
	if s.props[key] == nil {
		s.props[key] = map[string]fakeProp{}
	}
	for k, v := range kv {
		s.props[key][k] = fakeProp{value: v, expiry: exp}
	}
}

// recordJob is a cook's job as farmer records it from its sealed step
// events: its farmer.job_status row and its objects in the job bucket;
// s.mu is held.
func (s *Stack) recordJob(tid, sid, jid string) {
	s.jobStatus[tid+"/"+sid+"/"+jid] = "succeeded"
	s.putObject("jobs", "jobs/"+tid+"/"+sid+"/"+jid+"/steps.json", []byte("{}"))
}

func (s *Stack) putObject(bucket, key string, body []byte) {
	if s.objects[bucket] == nil {
		s.objects[bucket] = map[string][]byte{}
	}
	s.objects[bucket][key] = body
}

// audit writes a recipe audit record, as saasapi does on PUT and DELETE;
// s.mu is held.
func (s *Stack) audit(tid, name string) {
	day := time.Now().UTC().Format("2006-01-02")
	s.putObject("recipes", fmt.Sprintf("tenants/%s/recipe-audit/%s/%s-%s.json", tid, day, name, base32ish(8)), []byte("{}"))
}

// sleepFor is how long a cmd.run of a sleep keeps its item dispatching:
// the sleep, up to 8 s (the fake's clock is short), when it would finish
// inside its timeout (default 60 s); runCmd fails it otherwise.
func sleepFor(cmd string, args []string, timeout int) time.Duration {
	f := strings.Fields(cmd)
	var n int
	switch {
	case len(f) == 2 && f[0] == "sleep":
		n, _ = strconv.Atoi(f[1])
	case strings.Contains(strings.Join(args, " "), "Start-Sleep -Seconds "):
		n, _ = strconv.Atoi(strings.TrimSpace(strings.SplitAfter(strings.Join(args, " "), "Start-Sleep -Seconds ")[1]))
	default:
		return 0
	}
	if timeout == 0 {
		timeout = 60
	}
	if n <= 0 || n > timeout {
		return 0
	}
	return min(time.Duration(n)*time.Second, 8*time.Second)
}

// pendingItems counts a tenant's items still waiting; s.mu is held.
func (s *Stack) pendingItems(tid string) int {
	now, n := time.Now(), 0
	for _, b := range s.batches {
		if b.tenantID != tid {
			continue
		}
		for _, it := range b.items {
			if now.Before(it.until) {
				n++
			}
		}
	}
	return n
}

// sweep is the outbox sweeper's purge of a tenant offboarded for
// PurgeAfter, and the completion of a pending operator purge (a status
// poll after it was asked for); s.mu is held.
func (s *Stack) sweep(tid string, t *tenantRec) {
	if t.status != "offboarded" {
		return
	}
	for _, j := range s.jobs[tid] {
		if j.Type == "purge" && j.Status == "pending" {
			if time.Since(j.updated) > 500*time.Millisecond {
				s.purge(tid, t, j)
			}
			return
		}
	}
	if !t.offboarded.IsZero() && !time.Now().Before(t.offboarded.Add(s.PurgeAfter)) {
		s.purge(tid, t, s.addJob(tid, "purge", "pending", "retention"))
	}
}

// purge erases what a purge erases and leaves the tombstone; s.mu is held.
func (s *Stack) purge(tid string, t *tenantRec, j *provJob) {
	for id, k := range s.keys {
		if k.tenantID == tid {
			delete(s.keys, id)
		}
	}
	for a, o := range s.links {
		if strings.HasPrefix(o, tid+"/") {
			delete(s.links, a)
		}
	}
	for id, b := range s.batches {
		if b.tenantID == tid {
			delete(s.batches, id)
		}
	}
	for _, m := range []map[string]*sprout{s.sprouts} {
		for k := range m {
			if strings.HasPrefix(k, tid+"/") {
				delete(m, k)
			}
		}
	}
	for k := range s.recipeStore {
		if strings.HasPrefix(k, tid+"/") {
			delete(s.recipeStore, k)
		}
	}
	for _, bucket := range s.objects {
		for k := range bucket {
			if strings.HasPrefix(k, "tenants/"+tid+"/") || strings.HasPrefix(k, "jobs/"+tid+"/") || strings.HasPrefix(k, "sprouts/"+tid+"/") || strings.HasPrefix(k, tid+"/") {
				delete(bucket, k)
			}
		}
	}
	for k := range s.props {
		if strings.HasPrefix(k, tid+"/") {
			delete(s.props, k)
		}
	}
	for k := range s.markers {
		if strings.HasPrefix(k, tid+"/") {
			delete(s.markers, k)
		}
	}
	for k := range s.jobStatus {
		if strings.HasPrefix(k, tid+"/") {
			delete(s.jobStatus, k)
		}
	}
	delete(s.tenantBox, tid)
	t.status, t.name = "purged", ""
	j.Status, j.updated = "succeeded", time.Now()
}

// prune is saasapi's terminal-row prune at start; s.mu is held.
func (s *Stack) prune() {
	now := time.Now()
	cutoff := now.Add(-s.TerminalRowRetention)
	for id, b := range s.batches {
		done := b.created.Before(cutoff)
		for _, it := range b.items {
			if now.Before(it.until) || !it.updated.Before(cutoff) {
				done = false
			}
		}
		if done {
			delete(s.batches, id)
		}
	}
	for tid, jobs := range s.jobs {
		t := s.tenants[tid]
		if t == nil || (t.status != "pending" && t.status != "active" && t.status != "failed") {
			continue
		}
		var keep []*provJob
		for _, j := range jobs {
			if j.Type == "purge" || (j.Status != "succeeded" && j.Status != "failed") || !j.updated.Before(cutoff) {
				keep = append(keep, j)
			}
		}
		s.jobs[tid] = keep
	}
	for id, k := range s.keys {
		if k.expires.Before(cutoff) {
			delete(s.keys, id)
		}
	}
}

// sweepDated deletes the objects under prefix in bucket dated before
// days ago, with farmer's own dating and cutoff (internal/retention);
// s.mu is held.
func (s *Stack) sweepDated(bucket, prefix string, date retention.DateFunc, days int) {
	cutoff := retention.Cutoff(time.Now(), days)
	for k := range s.objects[bucket] {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if d, ok := date(k); ok && d.Before(cutoff) {
			delete(s.objects[bucket], k)
		}
	}
}

// Logf adds a line to a workload's log (farmer or saasapi).
func (s *Stack) logf(workload, format string, args ...any) {
	s.logs = append(s.logs, logLine{at: time.Now(), workload: workload, text: fmt.Sprintf(format, args...)})
}

var (
	accTenantRe = regexp.MustCompile(`^t_[a-z2-7]{16}$`)
	accBuckets  = map[string]bool{"recipes": true, "jobs": true, "sprout_jwts": true, "accounts": true, "logs": true}
)

// acceptance answers the fake acceptance.sh.
func (s *Stack) acceptance(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	verb, args := q.Get("verb"), q["arg"]
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	out, err := s.acceptanceVerb(verb, args, body)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err != nil {
		w.Header().Set("X-Exit-Code", "1")
		_, _ = io.WriteString(w, "[fake acceptance.sh] ERROR: "+err.Error()+"\n")
		return
	}
	b, _ := json.Marshal(out)
	w.Header().Set("X-Exit-Code", "0")
	_, _ = w.Write(append(b, '\n'))
}

func (s *Stack) acceptanceVerb(verb string, args []string, body []byte) (any, error) {
	want := func(n int) error {
		if len(args) != n {
			return fmt.Errorf("%s takes %d argument(s), got %d", verb, n, len(args))
		}
		return nil
	}
	tenant := func(i int) (string, error) {
		if i >= len(args) || !accTenantRe.MatchString(args[i]) {
			return "", fmt.Errorf("not a tenant ID")
		}
		return args[i], nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch verb {
	case "purge":
		tid, err := tenant(0)
		if err != nil {
			return nil, err
		}
		t, ok := s.tenants[tid]
		switch {
		case !ok:
			return map[string]any{"status": 404, "body": map[string]string{"error": "tenant_not_found", "message": "no such tenant"}}, nil
		case t.status != "offboarded":
			return map[string]any{"status": 409, "body": map[string]string{"error": "not_offboarded", "message": "the tenant is not offboarded"}}, nil
		}
		for _, j := range s.jobs[tid] {
			if j.Type == "purge" && j.Status == "pending" {
				return map[string]any{"status": 409, "body": map[string]string{"error": "purge_in_progress", "message": "a purge is pending"}}, nil
			}
		}
		j := s.addJob(tid, "purge", "pending", "operator")
		return map[string]any{"status": 202, "body": map[string]string{"tenant_id": tid, "job_id": j.ID, "status": "offboarded"}}, nil
	case "inventory":
		var spec struct {
			TenantID string `json:"tenant_id"`
			Tables   []string
			Objects  []struct{ Category, Bucket, Prefix string }
			Valkey   []struct{ Category, Pattern string }
			KV       []string `json:"openbao_kv"`
			Transit  []string
		}
		if err := json.Unmarshal(body, &spec); err != nil || !accTenantRe.MatchString(spec.TenantID) {
			return nil, fmt.Errorf("the inventory spec has no tenant_id")
		}
		return map[string]any{"counts": s.inventory(spec.TenantID, spec.Tables, spec.Objects, spec.Valkey, spec.KV, spec.Transit)}, nil
	case "provisioning-jobs":
		tid, err := tenant(0)
		if err != nil {
			return nil, err
		}
		jobs := []*provJob{}
		jobs = append(jobs, s.jobs[tid]...)
		return map[string]any{"jobs": jobs}, nil
	case "props":
		tid, err := tenant(0)
		if err != nil || want(2) != nil {
			return nil, fmt.Errorf("props <tenant_id> <sprout_id>")
		}
		var out []map[string]any
		s.hostProps(tid, args[1])
		names := []string{}
		for n := range s.props[tid+"/"+args[1]] {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			p := s.props[tid+"/"+args[1]][n]
			out = append(out, map[string]any{"name": n, "value": p.value, "expires_in": int(time.Until(p.expiry).Seconds())})
		}
		return map[string]any{"props": out}, nil
	case "job-status":
		if err := want(3); err != nil {
			return nil, err
		}
		st, ok := s.jobStatus[strings.Join(args, "/")]
		return map[string]any{"exists": ok, "status": st}, nil
	case "valkey-get":
		if err := want(1); err != nil {
			return nil, err
		}
		m := regexp.MustCompile(`^imas:upgrade:\{(t_[a-z2-7]{16}):([0-9a-z][-0-9_a-z]*)\}$`).FindStringSubmatch(args[0])
		if m == nil {
			return map[string]any{"exists": false, "value": ""}, nil
		}
		v, ok := s.markers[m[1]+"/"+m[2]]
		return map[string]any{"exists": ok, "value": v}, nil
	case "objects":
		if err := want(2); err != nil || !accBuckets[args[0]] {
			return nil, fmt.Errorf("objects <bucket> <prefix>")
		}
		keys := []string{}
		for k := range s.objects[args[0]] {
			if strings.HasPrefix(k, args[1]) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		return map[string]any{"keys": keys}, nil
	case "put-object", "delete-object":
		if err := want(2); err != nil || !accBuckets[args[0]] || strings.Contains(args[1], "..") {
			return nil, fmt.Errorf("%s <bucket> <key>", verb)
		}
		if verb == "put-object" {
			s.putObject(args[0], args[1], body)
			return map[string]any{"status": 200}, nil
		}
		delete(s.objects[args[0]], args[1])
		return map[string]any{"status": 204}, nil
	case "backdate":
		var spec struct {
			TenantID         string   `json:"tenant_id"`
			Seconds          int64    `json:"seconds"`
			Offboarded       bool     `json:"offboarded"`
			ProvisioningJobs []string `json:"provisioning_jobs"`
			Batches          []string `json:"batches"`
			EnrollmentKeys   []string `json:"enrollment_keys"`
		}
		if err := json.Unmarshal(body, &spec); err != nil || !accTenantRe.MatchString(spec.TenantID) || spec.Seconds <= 0 {
			return nil, fmt.Errorf("a backdate spec with tenant_id and seconds")
		}
		d, n := time.Duration(spec.Seconds)*time.Second, 0
		if t := s.tenants[spec.TenantID]; spec.Offboarded && t != nil && t.status == "offboarded" {
			t.offboarded = t.offboarded.Add(-d)
			n++
		}
		for _, j := range s.jobs[spec.TenantID] {
			for _, id := range spec.ProvisioningJobs {
				if j.ID == id {
					j.updated = j.updated.Add(-d)
					n++
				}
			}
		}
		for _, id := range spec.Batches {
			if b := s.batches[id]; b != nil && b.tenantID == spec.TenantID {
				b.created = b.created.Add(-d)
				for i := range b.items {
					b.items[i].updated = b.items[i].updated.Add(-d)
				}
				n += 1 + len(b.items)
			}
		}
		for _, id := range spec.EnrollmentKeys {
			if k := s.keys[id]; k != nil && k.tenantID == spec.TenantID {
				k.expires, k.created = k.expires.Add(-d), k.created.Add(-d)
				n++
			}
		}
		return map[string]any{"updated": n}, nil
	case "restart":
		if err := want(1); err != nil {
			return nil, err
		}
		switch args[0] {
		case "saasapi":
			s.prune()
		case "farmer":
		default:
			return nil, fmt.Errorf("unknown workload %s", args[0])
		}
		return map[string]any{"restarted": "imas-core-farmer-" + args[0]}, nil
	case "sweep":
		if err := want(1); err != nil {
			return nil, err
		}
		switch args[0] {
		case "recipe-audit":
			s.sweepDated("recipes", retention.RecipeAuditPrefix, retention.RecipeAuditDate, s.RecipeAuditDays)
		case "log-retention":
			s.sweepDated("logs", "logs/", retention.LogDate("logs/"), s.LogRetentionDays)
		default:
			return nil, fmt.Errorf("sweep recipe-audit or log-retention")
		}
		return map[string]any{"sweep": args[0]}, nil
	case "retention":
		return map[string]any{
			"farmer": map[string]string{"IMAS_RECIPE_AUDIT_RETENTION_DAYS": strconv.Itoa(s.RecipeAuditDays)},
			"saasapi": map[string]string{"SAASAPI_TERMINAL_ROW_RETENTION": hours(s.TerminalRowRetention),
				"SAASAPI_TENANT_PURGE_AFTER": hours(s.PurgeAfter), "SAASAPI_TENANT_PURGE_ENABLED": "true",
				"SAASAPI_ACTION_MAX_PENDING_PER_TENANT": strconv.Itoa(s.MaxPendingPerTenant)},
			"log_shipper":   map[string]bool{"daemonset": true, "configmap": true, "ready": true},
			"log_retention": map[string]any{"cronjob": true, "schedule": "17 3 * * *", "days": s.LogRetentionDays},
		}, nil
	case "log-count":
		if err := want(2); err != nil {
			return nil, err
		}
		secs, err := strconv.Atoi(args[1])
		if err != nil {
			return nil, err
		}
		since, n := time.Now().Add(-time.Duration(secs)*time.Second), 0
		for _, l := range s.logs {
			if l.workload == args[0] && !l.at.Before(since) && strings.Contains(l.text, string(body)) {
				n++
			}
		}
		return map[string]any{"count": n}, nil
	}
	return nil, fmt.Errorf("unknown verb %s", verb)
}

// hostProps refreshes the props a host's sprout reports in sealed facts
// every 100 s; s.mu is held.
func (s *Stack) hostProps(tid, sid string) {
	for _, h := range s.hosts {
		if TenantID(h.Tenant) == tid && h.SproutID == sid && !h.Stopped {
			goos := "linux"
			if h.OS == "windows" {
				goos = "windows"
			}
			s.setProps(tid, sid, map[string]string{"os": goos, "arch": "amd64", "hostname": h.VM, "sprout_version": "v" + h.Version}, time.Now().Add(5*time.Minute))
		}
	}
}

// inventory counts a tenant's data the way acceptance.sh does; s.mu is held.
func (s *Stack) inventory(tid string, tables []string, objects []struct{ Category, Bucket, Prefix string },
	valkey []struct{ Category, Pattern string }, kv, transit []string) map[string]int {
	out := map[string]int{}
	t, exists := s.tenants[tid]
	live := exists && t.status != "purged"
	count := func(pred func(string) bool, keys []string) int {
		n := 0
		for _, k := range keys {
			if pred(k) {
				n++
			}
		}
		return n
	}
	var sproutKeys []string
	boxKeys, jwts := 0, 0
	for k, sp := range s.sprouts {
		if strings.HasPrefix(k, tid+"/") {
			sproutKeys = append(sproutKeys, k)
			if sp.hasBoxKey {
				boxKeys++
			}
			if sp.userJWT != "" {
				jwts++
			}
		}
	}
	for _, table := range tables {
		n := 0
		switch table {
		case "farmer.pki_nkeys":
			n = len(sproutKeys)
		case "farmer.pki_sprout_box_keys":
			n = boxKeys
		case "farmer.sprout_user_jwt":
			n = jwts
		case "farmer.props":
			for k, m := range s.props {
				if strings.HasPrefix(k, tid+"/") {
					n += len(m)
				}
			}
		case "farmer.job_status":
			for k := range s.jobStatus {
				if strings.HasPrefix(k, tid+"/") {
					n++
				}
			}
		case "saas.enrollment_keys":
			for _, k := range s.keys {
				if k.tenantID == tid {
					n++
				}
			}
		case "saas.asset_links":
			for _, o := range s.links {
				if strings.HasPrefix(o, tid+"/") {
					n++
				}
			}
		case "saas.asset_action_batches", "saas.asset_action_items":
			for _, b := range s.batches {
				if b.tenantID == tid {
					if table == "saas.asset_action_batches" {
						n++
					} else {
						n += len(b.items)
					}
				}
			}
		case "saas.tenants", "farmer.pki_tenants":
			if exists {
				n = 1
			}
		case "saas.provisioning_jobs":
			n = len(s.jobs[tid])
		}
		out[table] = n
	}
	for _, o := range objects {
		var keys []string
		for k := range s.objects[o.Bucket] {
			keys = append(keys, k)
		}
		n := count(func(k string) bool { return strings.HasPrefix(k, o.Prefix) }, keys)
		if o.Bucket == "recipes" && strings.HasPrefix(o.Prefix, "tenants/") {
			for k := range s.recipeStore {
				if strings.HasPrefix(k, tid+"/") {
					n++
				}
			}
		}
		if o.Bucket == "sprout_jwts" {
			n += jwts
		}
		out[o.Category] = n
	}
	for _, v := range valkey {
		n := 0
		if strings.HasPrefix(v.Pattern, "imas:upgrade:") {
			for k := range s.markers {
				if strings.HasPrefix(k, tid+"/") {
					n++
				}
			}
		}
		if strings.HasPrefix(v.Pattern, "imas:accepted:") {
			n = len(sproutKeys)
		}
		out[v.Category] = n
	}
	for _, p := range kv {
		out["kv:"+p] = b2i(live && strings.HasSuffix(p, "/"+tid))
	}
	for _, k := range transit {
		out["transit:"+k] = b2i(live && strings.HasSuffix(k, "-"+tid))
	}
	return out
}

// hours writes d as the chart's values do, "24h".
func hours(d time.Duration) string { return strconv.Itoa(int(d/time.Hour)) + "h" }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// legacyNKey serves a standalone farmer's GET /pki/nkeynonce and PUT
// /pki/putnkey (enrolment off), with farmer's own nonce and proof checks
// (internal/pki nkeynonce.go). The hosted stack serves neither; the fake
// serves both, so N1's standalone path is exercised end to end.
func (s *Stack) legacyNKey(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/pki/nkeynonce" && r.Method == http.MethodGet:
		n, err := pki.IssueNKeyNonce()
		if err != nil {
			w.WriteHeader(503)
			return
		}
		writeJSON(w, 200, pki.NKeyNonce{Nonce: n})
	case r.URL.Path == "/pki/putnkey" && r.Method == http.MethodPut:
		var sub pki.KeySubmission
		if json.NewDecoder(r.Body).Decode(&sub) != nil || !pki.IsValidSproutID(sub.SproutID) {
			w.WriteHeader(400)
			return
		}
		if pki.VerifyNKeySubmission(sub) != nil {
			w.WriteHeader(403)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		key := "standalone/" + sub.SproutID
		if sp, ok := s.sprouts[key]; ok && sp.nkey != sub.NKey {
			// A different key for a known ID goes to the next free
			// suffix as rejected, never over the one on file.
			for i := 1; ; i++ {
				k := fmt.Sprintf("%s_%d", key, i)
				if _, taken := s.sprouts[k]; !taken {
					s.sprouts[k] = &sprout{nkey: sub.NKey}
					break
				}
			}
		} else if !ok {
			s.sprouts[key] = &sprout{nkey: sub.NKey}
		}
		writeJSON(w, 200, map[string]bool{"success": true})
	default:
		w.WriteHeader(405)
	}
}
