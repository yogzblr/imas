package lease

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// JobLeaseTTLEnv names the lease TTL of farmer's background jobs
// (job_leases), a Go duration. Unset, unparsable or not positive means
// DefaultJobLeaseTTL.
const JobLeaseTTLEnv = "IMAS_JOB_LEASE_TTL"

// DefaultJobLeaseTTL is the job lease TTL when IMAS_JOB_LEASE_TTL is unset.
const DefaultJobLeaseTTL = 120 * time.Second

// JobTTL returns the job lease TTL IMAS_JOB_LEASE_TTL sets.
func JobTTL() time.Duration {
	if d, err := time.ParseDuration(os.Getenv(JobLeaseTTLEnv)); err == nil && d > 0 {
		return d
	}
	return DefaultJobLeaseTTL
}

// JobLease is a farmer.job_leases row (migration farmer 00004). It is
// exported for tests that create the table with AutoMigrate.
type JobLease struct {
	Name       string     `gorm:"column:name;primaryKey;size:128"`
	LeaseOwner *string    `gorm:"column:lease_owner;size:128"`
	LeaseUntil *time.Time `gorm:"column:lease_until"`
	LastRunAt  *time.Time `gorm:"column:last_run_at"`
}

// TableName is job_leases.
func (JobLease) TableName() string { return string(JobLeases) }

var (
	replicaOnce sync.Once
	replicaID   string
)

// replica is this process's owner prefix: its host name (the pod name)
// plus a random suffix, so two processes on one host differ.
func replica() string {
	replicaOnce.Do(func() {
		host, _ := os.Hostname()
		if len(host) > 64 {
			host = host[:64]
		}
		var b [8]byte
		_, _ = rand.Read(b[:])
		replicaID = host + "-" + hex.EncodeToString(b[:])
	})
	return replicaID
}

// runOwner is the owner of one Run call: the replica plus a random token,
// so two calls on one replica never take each other's lease as their own.
func runOwner() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return replica() + "-" + hex.EncodeToString(b[:])
}

// Run runs fn as the job name on at most one replica at a time, and at
// most once per minInterval across all replicas, using the job_leases row
// of that name on db. See Leases.Run.
//
// A nil db runs fn directly and reports true: a process with no shared
// database (a unit test, a single process) has no other replica to keep
// out.
func Run(ctx context.Context, db *gorm.DB, name string, ttl, minInterval time.Duration, fn func(context.Context) error) (bool, error) {
	if db == nil {
		return true, fn(ctx)
	}
	return New(db, nil).Run(ctx, name, ttl, minInterval, fn)
}

// Run runs fn as the job name if this call takes the job's lease and the
// job's last successful run started at least minInterval ago. It reports
// whether fn ran, and returns fn's error. Not running (another replica
// holds the lease, or ran the job too recently) is not an error.
//
//  1. The row is created if missing (INSERT IGNORE), so jobs named on
//     demand (pushall:<tenant_id>) need no seed row.
//  2. The lease is taken for ttl under an owner unique to this call.
//  3. last_run_at is read; if it is within minInterval of now the lease
//     is released and fn does not run.
//  4. last_run_at is set to now while the lease is held, so a replica
//     that dies inside fn still counts as having run.
//  5. fn runs; the lease is renewed every ttl/3 meanwhile, and fn's
//     context is cancelled if a renewal finds the lease taken.
//  6. If fn failed, last_run_at goes back to its old value, so a retry
//     on any replica need not wait out minInterval.
//  7. The lease is released.
//
// fn must be safe to run again: a replica whose clock or database
// stalls past ttl can overlap the next holder.
func (l *Leases) Run(ctx context.Context, name string, ttl, minInterval time.Duration, fn func(context.Context) error) (bool, error) {
	if name == "" || len(name) > MaxOwnerLen {
		return false, fmt.Errorf("%w: job name must be 1 to %d bytes", ErrInvalid, MaxOwnerLen)
	}
	if ttl <= 0 || minInterval < 0 {
		return false, fmt.Errorf("%w: ttl must be positive and minInterval not negative", ErrInvalid)
	}
	db := l.db.WithContext(ctx)
	if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&JobLease{Name: name}).Error; err != nil {
		return false, fmt.Errorf("lease: creating job %s: %w", name, err)
	}
	key := []any{name}
	owner := runOwner()
	got, err := l.Acquire(ctx, JobLeases, key, owner, ttl)
	if err != nil || !got {
		return false, err
	}
	release := func() {
		_, _ = l.Release(context.WithoutCancel(ctx), JobLeases, key, owner)
	}

	var row JobLease
	if err := db.Where("name = ?", name).Take(&row).Error; err != nil {
		release()
		return false, fmt.Errorf("lease: reading job %s: %w", name, err)
	}
	now := dbTime(l.now())
	if row.LastRunAt != nil && now.Before(row.LastRunAt.Add(minInterval)) {
		release()
		return false, nil
	}
	r := db.Model(&JobLease{}).Where("name = ? AND lease_owner = ?", name, owner).UpdateColumn("last_run_at", now)
	if r.Error != nil {
		release()
		return false, fmt.Errorf("lease: recording job %s run: %w", name, r.Error)
	}
	if r.RowsAffected != 1 {
		// MySQL counts changed rows: last_run_at may already hold now.
		// Renew tells that apart from the lease having been taken.
		if ok, err := l.Renew(ctx, JobLeases, key, owner, ttl); err != nil || !ok {
			return false, err
		}
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopped := make(chan struct{})
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		t := time.NewTicker(ttl / 3)
		defer t.Stop()
		for {
			select {
			case <-stopped:
				return
			case <-runCtx.Done():
				return
			case <-t.C:
				if ok, err := l.Renew(runCtx, JobLeases, key, owner, ttl); err == nil && !ok {
					cancel()
					return
				}
			}
		}
	}()
	fnErr := fn(runCtx)
	close(stopped)
	<-renewed
	if fnErr != nil {
		// Only while still holding the lease: a later holder's run stands.
		db := l.db.WithContext(context.WithoutCancel(ctx))
		if err := db.Model(&JobLease{}).Where("name = ? AND lease_owner = ?", name, owner).
			UpdateColumn("last_run_at", row.LastRunAt).Error; err != nil {
			fnErr = errors.Join(fnErr, fmt.Errorf("lease: restoring job %s last run: %w", name, err))
		}
	}
	release()
	return true, fnErr
}
