package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/pressly/goose/v3"
)

// UpResult is what one Up did.
type UpResult struct {
	From, To int64
	// Applied lists the versions this run applied, in order.
	Applied []int64
}

// Up migrates the schema db is connected to up to s.Latest. db must be
// connected as that schema's owner (farmer's user for Farmer, saasapi's
// for Saas), so the owner stays the schema's only writer. The caller holds
// the migration lock (AcquireLock) for the whole run.
//
// In order: refuse a schema whose floor excludes this binary; if the
// schema is already ahead of this binary, apply nothing (the rollback
// case); otherwise raise the recorded floor to s.CompatibleFrom, then
// apply what's pending. The floor goes first so that a run that fails
// partway never leaves a schema that claims to support binaries its
// applied migrations already broke. It only ever rises.
func Up(ctx context.Context, db *sql.DB, s Set, logf func(format string, args ...any)) (UpResult, error) {
	st, err := ReadState(ctx, db)
	if err != nil {
		return UpResult{}, err
	}
	res := UpResult{From: st.Version, To: st.Version}
	if st.Floor > s.latest {
		// Possibly with the version still behind: a newer binary's run
		// raised the floor and then failed. Either way, not this binary's.
		return res, fmt.Errorf("%s: %w: a newer binary set the schema's floor to %d, this binary is built for %d",
			s.name, ErrSchemaTooNew, st.Floor, s.latest)
	}
	if st.Version > s.latest {
		logf("%s: schema version %d is newer than this binary's %d and still supports it; nothing to apply", s.name, st.Version, s.latest)
		return res, nil
	}
	if err := raiseFloor(ctx, db, s.compatibleFrom); err != nil {
		return res, fmt.Errorf("%s: %w", s.name, err)
	}
	p, err := goose.NewProvider(goose.DialectMySQL, db, s.fsys, goose.WithDisableGlobalRegistry(true))
	if err != nil {
		return res, fmt.Errorf("%s: %w", s.name, err)
	}
	results, err := p.Up(ctx)
	if perr, ok := errors.AsType[*goose.PartialError](err); ok {
		results = perr.Applied
	}
	for _, r := range results {
		if r.Error == nil {
			res.Applied = append(res.Applied, r.Source.Version)
			res.To = r.Source.Version
			logf("%s: applied %s in %s", s.name, r.Source.Path, r.Duration)
		}
	}
	if err != nil {
		return res, fmt.Errorf("%s: %w", s.name, err)
	}
	return res, nil
}

func raiseFloor(ctx context.Context, db *sql.DB, floor int64) error {
	if _, err := db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS `"+InfoTable+"` ("+
		"`id` tinyint unsigned NOT NULL,"+
		"`min_compatible_version` bigint NOT NULL,"+
		"`updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),"+
		"PRIMARY KEY (`id`)) ENGINE=InnoDB"); err != nil {
		return fmt.Errorf("creating %s: %w", InfoTable, err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO `"+InfoTable+"` (`id`, `min_compatible_version`) VALUES (1, ?)"+
		" ON DUPLICATE KEY UPDATE `min_compatible_version` = GREATEST(`min_compatible_version`, ?)", floor, floor); err != nil {
		return fmt.Errorf("recording compatibility floor: %w", err)
	}
	return nil
}
