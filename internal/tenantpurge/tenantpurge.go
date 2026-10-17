// Package tenantpurge erases what one tenant left behind once it is
// offboarded (S6, docs/briefs/S6-tenant-erasure.md): the inventory of
// where a tenant's data lives, and the bounded, tenant-exact deletes the
// purge runs over it. FLAG FOR SECURITY REVIEW: everything here deletes.
//
// Every delete names the tenant exactly: a row by tenant_id equality, an
// object by a key prefix whose tenant segment is the whole tenant ID
// followed by "/", a Valkey key by a pattern whose tenant part ends at a
// separator no tenant ID contains. A tenant ID is [0-9A-Za-z_-]{1,191}
// (internal/pki IsValidTenantID), so it has no SQL, glob or path
// metacharacter; every function here refuses one that doesn't match.
// Deletes run in bounded batches and are idempotent: run again after a
// partial run, they delete what is left and report zero for what is gone.
//
// The inventory (inventory.go) is what drives the purge, not a copy of
// it: farmer's purge (internal/natsapi tenant_purge.go) and saasapi's
// (applyProvisioningResult) iterate these lists, and inventory_test.go
// fails when a table with a tenant_id column, an object key root or a
// Valkey key prefix exists that is in neither a purge list nor a keep
// list.
package tenantpurge

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/valkey-io/valkey-go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/objectstore"
)

// DefaultBatch is how many rows, objects or keys one delete round takes.
const DefaultBatch = 500

// tenantIDPattern is internal/pki's IsValidTenantID, repeated here so this
// package depends on nothing of ours.
var tenantIDPattern = regexp.MustCompile(`^[0-9A-Za-z_-]{1,191}$`)

// tableName is what a table name in the inventory may look like.
var tableName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ErrInvalidTenantID is a tenant ID that isn't one; nothing is deleted.
var ErrInvalidTenantID = errors.New("tenantpurge: invalid tenant id")

// ValidTenantID reports whether id is a tenant ID.
func ValidTenantID(id string) bool { return tenantIDPattern.MatchString(id) }

func checkTenant(id string) error {
	if !ValidTenantID(id) {
		return fmt.Errorf("%w: %q", ErrInvalidTenantID, id)
	}
	return nil
}

func batchOf(n int) int {
	if n < 1 {
		return DefaultBatch
	}
	return n
}

// DeleteRows deletes every row of table whose tenant_id is tenantID, at
// most batch rows per statement, and returns how many it deleted. table
// must be one of the inventory's tables. On MySQL each round is DELETE
// ... WHERE tenant_id = ? LIMIT n; on SQLite (tests) the same bound goes
// through rowid.
func DeleteRows(ctx context.Context, db *gorm.DB, table, tenantID string, batch int) (int64, error) {
	if err := checkTenant(tenantID); err != nil {
		return 0, err
	}
	if !tableName.MatchString(table) {
		return 0, fmt.Errorf("tenantpurge: invalid table name %q", table)
	}
	if db == nil {
		return 0, errors.New("tenantpurge: no database")
	}
	n := batchOf(batch)
	stmt := "DELETE FROM `" + table + "` WHERE `tenant_id` = ? LIMIT ?"
	if db.Dialector.Name() == "sqlite" {
		stmt = "DELETE FROM `" + table + "` WHERE rowid IN (SELECT rowid FROM `" + table + "` WHERE `tenant_id` = ? LIMIT ?)"
	}
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		res := db.WithContext(ctx).Exec(stmt, tenantID, n)
		if res.Error != nil {
			return total, fmt.Errorf("tenantpurge: deleting from %s: %w", table, res.Error)
		}
		total += res.RowsAffected
		if res.RowsAffected < int64(n) {
			return total, nil
		}
	}
}

// Objects is the part of an *objectstore.Store a purge uses.
type Objects interface {
	ListPage(ctx context.Context, prefix, startAfter string, max int) ([]objectstore.ObjectInfo, bool, error)
	Delete(ctx context.Context, key string) error
}

// DeleteObjects deletes every object under prefix, listing at most batch
// keys at a time, and returns how many it deleted. prefix must end in
// "/" and its last segment must be tenantID, so no other tenant's keys
// (a tenant whose ID tenantID is a prefix of, say) can match. Each round
// lists from the start: what it deleted is gone, so a key a round could
// not delete stops the run with an error instead of being skipped.
func DeleteObjects(ctx context.Context, store Objects, prefix, tenantID string, batch int) (int64, error) {
	if err := checkTenant(tenantID); err != nil {
		return 0, err
	}
	if !strings.HasSuffix(prefix, "/"+tenantID+"/") && prefix != tenantID+"/" {
		return 0, fmt.Errorf("tenantpurge: prefix %q does not end in the tenant's own segment", prefix)
	}
	if store == nil {
		return 0, errors.New("tenantpurge: no object store")
	}
	n := batchOf(batch)
	var total int64
	for {
		page, _, err := store.ListPage(ctx, prefix, "", n)
		if err != nil {
			return total, fmt.Errorf("tenantpurge: listing a tenant prefix: %w", err)
		}
		if len(page) == 0 {
			return total, nil
		}
		for _, o := range page {
			if !strings.HasPrefix(o.Key, prefix) {
				return total, errors.New("tenantpurge: the store listed a key outside the tenant prefix; nothing more deleted")
			}
			if err := store.Delete(ctx, o.Key); err != nil {
				return total, fmt.Errorf("tenantpurge: deleting an object under a tenant prefix: %w", err)
			}
			total++
		}
	}
}

// DeleteValkeyKeys deletes every key matching pattern on every node of
// client (SCAN with MATCH and COUNT batch, then one DEL per key, so each
// goes to its own slot in a cluster), and returns how many existed.
// pattern must be one of the inventory's ValkeyPatterns for tenantID.
func DeleteValkeyKeys(ctx context.Context, client valkey.Client, pattern string, batch int) (int64, error) {
	if client == nil {
		return 0, errors.New("tenantpurge: no Valkey client")
	}
	n := int64(batchOf(batch))
	var total int64
	for _, node := range client.Nodes() {
		var cursor uint64
		for {
			if err := ctx.Err(); err != nil {
				return total, err
			}
			entry, err := node.Do(ctx, node.B().Scan().Cursor(cursor).Match(pattern).Count(n).Build()).AsScanEntry()
			if err != nil {
				return total, fmt.Errorf("tenantpurge: scanning Valkey: %w", err)
			}
			if len(entry.Elements) > 0 {
				cmds := make(valkey.Commands, 0, len(entry.Elements))
				for _, k := range entry.Elements {
					cmds = append(cmds, client.B().Del().Key(k).Build())
				}
				for _, r := range client.DoMulti(ctx, cmds...) {
					d, err := r.AsInt64()
					if err != nil {
						return total, fmt.Errorf("tenantpurge: deleting a Valkey key: %w", err)
					}
					total += d
				}
			}
			cursor = entry.Cursor
			if cursor == 0 {
				break
			}
		}
	}
	return total, nil
}
