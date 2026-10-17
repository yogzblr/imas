package natsapi

// Farmer's half of erasing an offboarded tenant's data (S6,
// docs/briefs/S6-tenant-erasure.md): internal.tenant.purge in,
// internal.tenant.purged.{job_id} out, sealed both ways like the other
// tenant subjects (tenant_provision.go). FLAG FOR SECURITY REVIEW: this
// deletes a tenant's data for good.
//
// Before anything is deleted, the guards (pki.CheckTenantPurgeable): the
// tenant ID is valid, it is not the legacy current tenant, and farmer's
// own registry shows it deprovisioned. Otherwise nothing is deleted and
// the result is a refusal (purge_refused, or invalid_tenant_id).
//
// Then the steps, in an order that leaves the tenant locked out and the
// rest re-runnable if the process dies part way (S6 decision 7): live
// caches (Valkey), farmer-schema rows, the tombstone's own data, object
// store prefixes, OpenBao KV (the tenant's keypair, tenantpurge.KVPaths),
// and the tenant's Transit keys last. Each step deletes by tenant_id
// equality or an exact tenant prefix, in bounded batches, under its own
// timeout. A step that fails stops the run: the result is
// purge_incomplete, naming the step, with the counts so far. Running the purge again (the SaaS
// API's sweeper does, at most daily, or an operator at once) finishes it;
// a purge of a tenant already purged deletes nothing and succeeds.
//
// The saas-schema rows are not farmer's: farmer's database user may only
// read that schema. saasapi deletes them when it applies the successful
// result (tenantpurge.SaasTables).
//
// One replica at a time per tenant: the run holds the farmer job lease
// purge:<tenant_id>. A copy re-sent while another replica is still
// running is dropped unanswered, and the SaaS API sends it again later.
//
// Every run writes one platform audit entry: the tenant ID, the job ID,
// the trigger, the outcome and the counts per category. Numbers and
// fixed names only, never a table row, object key or content.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/jobs"
	"github.com/yogzblr/imas/internal/lease"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/tenantpurge"
)

// auditActionTenantPurge is the purge's audit action, the subject name.
const auditActionTenantPurge = controlplane.SubjectTenantPurge

// purgeStepTimeout bounds each purge step. A tenant too large to erase
// in it stops with purge_incomplete; the next run carries on where it
// stopped, since every step deletes only what is left.
const purgeStepTimeout = 10 * time.Minute

// purgeBatch is how many rows, objects or keys one delete round takes.
const purgeBatch = tenantpurge.DefaultBatch

// purgeOps is the erasure, step by step; tests replace entries. Every
// step returns its counts, even when it fails part way.
type purgeOps struct {
	check     func(tenantID string) error
	valkey    func(ctx context.Context, tenantID string) (map[string]int64, error)
	db        func(ctx context.Context, tenantID string) (map[string]int64, error)
	tombstone func(ctx context.Context, tenantID string) error
	objects   func(ctx context.Context, tenantID string) (map[string]int64, error)
	kv        func(ctx context.Context, tenantID string) (map[string]int64, error)
	transit   func(ctx context.Context, tenantID string) (map[string]int64, error)
	// runLeased runs fn under the tenant's purge lease and reports
	// whether it ran.
	runLeased func(ctx context.Context, tenantID string, fn func(context.Context) error) (bool, error)
}

var purge = purgeOps{
	check: pki.CheckTenantPurgeable,
	valkey: func(ctx context.Context, t string) (map[string]int64, error) {
		return heartbeat.PurgeTenant(ctx, t, purgeBatch)
	},
	db: func(ctx context.Context, t string) (map[string]int64, error) {
		return pki.PurgeTenantRows(ctx, t, purgeBatch)
	},
	tombstone: pki.ScrubTenantTombstone,
	objects:   purgeTenantObjects,
	kv:        purgeTenantKV,
	transit: func(ctx context.Context, t string) (map[string]int64, error) {
		n, err := pki.DestroyTenantKeys(ctx, t)
		return map[string]int64{"transit.keys": n}, err
	},
	runLeased: func(ctx context.Context, t string, fn func(context.Context) error) (bool, error) {
		l := pki.JobLeases(nil)
		if l == nil {
			return true, fn(ctx)
		}
		return l.Run(ctx, purgeLeaseName(t), lease.JobTTL(), 0, fn)
	},
}

// purgeLeaseName is tenantID's farmer.job_leases row for its purge.
func purgeLeaseName(tenantID string) string { return "purge:" + tenantID }

// purgeTenantObjects erases tenantID's objects in every bucket
// (tenantpurge.ObjectPrefixes): the recipe bucket's tenant and staged
// recipe prefixes, the job bucket's and the sprout JWT bucket's.
func purgeTenantObjects(ctx context.Context, tenantID string) (map[string]int64, error) {
	counts, err := cook.PurgeTenantObjects(ctx, tenantID, purgeBatch)
	if err != nil {
		return counts, err
	}
	n, err := jobs.PurgeTenantObjects(ctx, tenantID, purgeBatch)
	counts["objects.jobs"] = n
	if err != nil {
		return counts, err
	}
	n, err = pki.PurgeTenantSproutJWTs(ctx, tenantID, purgeBatch)
	counts["objects.sprout_jwts"] = n
	return counts, err
}

// purgeTenantKV is the OpenBao KV step: the tenant's payload-encryption
// keypair (tenantpurge.KVPaths), every version and its metadata. Without
// a tenant box OpenBao client the step fails rather than report the
// keypair gone.
func purgeTenantKV(ctx context.Context, tenantID string) (map[string]int64, error) {
	n, err := pki.PurgeTenantBoxKeys(ctx, tenantID)
	return map[string]int64{"kv.tenant_box_keys": n}, err
}

// purgeAudit is the purge's audit entry params: identifiers, the
// outcome and counts, nothing else.
type purgeAudit struct {
	JobID      string                 `json:"job_id"`
	TenantID   string                 `json:"tenant_id"`
	Trigger    string                 `json:"trigger"`
	Status     string                 `json:"status"`
	ErrorCode  controlplane.ErrorCode `json:"error_code,omitempty"`
	FailedStep string                 `json:"failed_step,omitempty"`
	Counts     map[string]int64       `json:"counts"`
}

// handleTenantPurge runs data, an opened internal.tenant.purge request's
// params, and publishes its sealed result.
func handleTenantPurge(nc *nats.Conn, data []byte) {
	var req controlplane.TenantPurgeRequest
	if err := json.Unmarshal(data, &req); err != nil {
		log.Errorf("natsapi: dropping malformed %s request: %v", controlplane.SubjectTenantPurge, err)
		return
	}
	if !controlplane.ValidJobID(req.JobID) {
		log.Errorf("natsapi: dropping %s request with invalid job_id %q (tenant %q)", controlplane.SubjectTenantPurge, req.JobID, req.TenantID)
		return
	}
	res, ran := runTenantPurge(context.Background(), req)
	if !ran {
		return
	}
	publishTenantResult(nc, controlplane.TenantJobPurge, res)
}

// runTenantPurge runs req's purge and audits it. ran is false when
// another replica holds the tenant's purge lease (or the lease couldn't
// be read): nothing ran, nothing is audited or published.
func runTenantPurge(ctx context.Context, req controlplane.TenantPurgeRequest) (res controlplane.TenantResult, ran bool) {
	res = controlplane.TenantResult{JobID: req.JobID, TenantID: req.TenantID, Status: controlplane.StatusPurged, Counts: map[string]int64{}}
	var runErr error
	switch err := checkPurgeRequest(req); {
	case err != nil:
		res, runErr = refusePurge(res, err), err
	default:
		var leaseErr error
		ran, leaseErr = purge.runLeased(ctx, req.TenantID, func(ctx context.Context) error {
			// The guards again, under the lease: what they read is what
			// the steps act on.
			if err := purge.check(req.TenantID); err != nil {
				res = refusePurge(res, err)
				return err
			}
			res, runErr = runPurgeSteps(ctx, res)
			return runErr
		})
		if !ran {
			if leaseErr != nil {
				log.Errorf("natsapi: purge of tenant %q (job %s) not started: purge lease: %v", req.TenantID, req.JobID, leaseErr)
			} else {
				log.Infof("natsapi: purge of tenant %q (job %s) is running on another replica; not started here", req.TenantID, req.JobID)
			}
			return res, false
		}
		if runErr == nil && leaseErr != nil {
			log.Warnf("natsapi: purge of tenant %q (job %s) finished; releasing its lease: %v", req.TenantID, req.JobID, leaseErr)
		}
	}
	if runErr != nil {
		log.Errorf("natsapi: purge of tenant %q (job %s, trigger %s): %s: %v", req.TenantID, req.JobID, req.Trigger, res.ErrorCode, runErr)
	} else {
		log.Infof("natsapi: purged tenant %q (job %s, trigger %s): %v", req.TenantID, req.JobID, req.Trigger, res.Counts)
	}
	auditTenantPurge(req, res)
	return res, true
}

// checkPurgeRequest is what is checked of a request before the lease: a
// known trigger, and the guards.
func checkPurgeRequest(req controlplane.TenantPurgeRequest) error {
	if !controlplane.ValidPurgeTrigger(req.Trigger) {
		return fmt.Errorf("%w: unknown trigger %q", pki.ErrTenantPurgeRefused, req.Trigger)
	}
	return purge.check(req.TenantID)
}

// refusePurge makes res the refusal for err: nothing was deleted.
func refusePurge(res controlplane.TenantResult, err error) controlplane.TenantResult {
	res.Status = controlplane.StatusFailed
	switch {
	case errors.Is(err, pki.ErrTenantIDInvalid):
		res.ErrorCode = controlplane.ErrorInvalidTenantID
	case errors.Is(err, pki.ErrTenantPurgeRefused):
		res.ErrorCode = controlplane.ErrorPurgeRefused
	default:
		res.ErrorCode = controlplane.ErrorInternal
	}
	return res
}

// runPurgeSteps runs every step in order, each under purgeStepTimeout,
// adding its counts to res, and stops at the first that fails.
func runPurgeSteps(ctx context.Context, res controlplane.TenantResult) (controlplane.TenantResult, error) {
	t := res.TenantID
	steps := []struct {
		name string
		run  func(ctx context.Context) (map[string]int64, error)
	}{
		{controlplane.PurgeStepValkey, func(ctx context.Context) (map[string]int64, error) { return purge.valkey(ctx, t) }},
		{controlplane.PurgeStepDB, func(ctx context.Context) (map[string]int64, error) { return purge.db(ctx, t) }},
		{controlplane.PurgeStepTombstone, func(ctx context.Context) (map[string]int64, error) { return nil, purge.tombstone(ctx, t) }},
		{controlplane.PurgeStepObjects, func(ctx context.Context) (map[string]int64, error) { return purge.objects(ctx, t) }},
		{controlplane.PurgeStepKV, func(ctx context.Context) (map[string]int64, error) { return purge.kv(ctx, t) }},
		{controlplane.PurgeStepTransit, func(ctx context.Context) (map[string]int64, error) { return purge.transit(ctx, t) }},
	}
	for _, s := range steps {
		sctx, cancel := context.WithTimeout(ctx, purgeStepTimeout)
		counts, err := s.run(sctx)
		cancel()
		for k, v := range counts {
			if controlplane.ValidPurgeCategory(k) {
				res.Counts[k] += v
			}
		}
		if err != nil {
			res.Status, res.ErrorCode, res.FailedStep = controlplane.StatusFailed, controlplane.ErrorPurgeIncomplete, s.name
			if errors.Is(err, pki.ErrTenantPurgeRefused) || errors.Is(err, pki.ErrTenantIDInvalid) {
				res.ErrorCode = refusePurge(res, err).ErrorCode
			}
			return res, fmt.Errorf("step %s: %w", s.name, err)
		}
	}
	return res, nil
}

// auditTenantPurge writes the purge's one platform audit entry. Its error
// is a fixed sentence naming the outcome, never the underlying error,
// whose text can carry object keys or database detail (that stays in
// farmer's log, above).
func auditTenantPurge(req controlplane.TenantPurgeRequest, res controlplane.TenantResult) {
	params, err := json.Marshal(purgeAudit{
		JobID: req.JobID, TenantID: req.TenantID, Trigger: req.Trigger, Status: res.Status,
		ErrorCode: res.ErrorCode, FailedStep: res.FailedStep, Counts: res.Counts,
	})
	if err != nil {
		log.Errorf("natsapi: encoding the audit entry of purge job %s: %v", req.JobID, err)
		return
	}
	var outcome error
	switch {
	case res.FailedStep != "":
		outcome = fmt.Errorf("tenant purge stopped at step %s (%s)", res.FailedStep, res.ErrorCode)
	case res.Status == controlplane.StatusFailed:
		outcome = fmt.Errorf("tenant purge refused (%s); nothing deleted", res.ErrorCode)
	}
	auditTenantAction(auditActionTenantPurge, params, res, outcome)
}
