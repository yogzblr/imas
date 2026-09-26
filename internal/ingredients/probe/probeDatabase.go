package probe

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

var (
	ErrProbeMissingDriver    = errors.New("probe.database requires a driver")
	ErrProbeMissingDSN       = errors.New("probe.database requires a dsn")
	ErrProbeMissingQuery     = errors.New("probe.database requires a query")
	ErrProbeRowCountMismatch = errors.New("probe.database row count did not match expectations")
	ErrProbeValueMismatch    = errors.New("probe.database first row/column value did not match expect_value")
)

var databaseMethodProps = ingredients.MethodPropsSet{
	// driver must already be registered with database/sql (via that
	// driver's own package import) elsewhere in the running binary --
	// probe.database does not bundle a driver itself. See package doc.
	ingredients.MethodProps{Key: "driver", Type: "string", IsReq: true, Description: "database/sql driver name, already registered elsewhere"},
	ingredients.MethodProps{Key: "dsn", Type: "string", IsReq: true, Description: "data source name / connection string"},
	ingredients.MethodProps{Key: "query", Type: "string", IsReq: true, Description: "query to run"},
	ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false, Description: "query timeout, e.g. 5s (default 5s)"},
	ingredients.MethodProps{Key: "expect_value", Type: "string", IsReq: false, Description: "expected string value of the first row's first column"},
}

// dbOpen is overridden in tests to avoid depending on a real database/sql
// driver being registered in the test binary.
var dbOpen = sql.Open

func (p Probe) probeDatabase(ctx context.Context) (cook.Result, error) {
	driver, ok := p.params["driver"].(string)
	if !ok || driver == "" {
		return cook.Result{Succeeded: false, Failed: true}, ErrProbeMissingDriver
	}
	dsn, ok := p.params["dsn"].(string)
	if !ok || dsn == "" {
		return cook.Result{Succeeded: false, Failed: true}, ErrProbeMissingDSN
	}
	query, ok := p.params["query"].(string)
	if !ok || query == "" {
		return cook.Result{Succeeded: false, Failed: true}, ErrProbeMissingQuery
	}

	timeout := 5 * time.Second
	if ts, ok := p.params["timeout"].(string); ok && ts != "" {
		d, err := time.ParseDuration(ts)
		if err != nil {
			return cook.Result{Succeeded: false, Failed: true}, errors.Join(ErrProbeInvalidTimeout, err)
		}
		timeout = d
	}
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	db, err := dbOpen(driver, dsn)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true}, fmt.Errorf("open %s: %w", driver, err)
	}
	defer db.Close()

	rows, err := db.QueryContext(queryCtx, query)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true}, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true}, err
	}

	rowCount := 0
	var firstValue string
	haveFirstValue := false
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return cook.Result{Succeeded: false, Failed: true}, err
		}
		if !haveFirstValue && len(vals) > 0 {
			firstValue = fmt.Sprintf("%v", vals[0])
			haveFirstValue = true
		}
		rowCount++
	}
	if err := rows.Err(); err != nil {
		return cook.Result{Succeeded: false, Failed: true}, err
	}

	notes := []fmt.Stringer{
		cook.Snprintf("query returned %d row(s)", rowCount),
	}
	if haveFirstValue {
		notes = append(notes, cook.Snprintf("%s", firstValue))
	}

	if want, ok := p.params["expect_row_count"]; ok {
		wantN, convErr := toInt(want)
		if convErr != nil {
			return cook.Result{Succeeded: false, Failed: true, Notes: notes}, convErr
		}
		if rowCount != wantN {
			return cook.Result{Succeeded: false, Failed: true, Notes: notes},
				fmt.Errorf("%w: got %d, want %d", ErrProbeRowCountMismatch, rowCount, wantN)
		}
	}

	if want, ok := p.params["expect_value"].(string); ok {
		if !haveFirstValue || firstValue != want {
			return cook.Result{Succeeded: false, Failed: true, Notes: notes},
				fmt.Errorf("%w: got %q, want %q", ErrProbeValueMismatch, firstValue, want)
		}
	}

	return cook.Result{Succeeded: true, Failed: false, Changed: false, Notes: notes}, nil
}

func toInt(v interface{}) (int, error) {
	switch t := v.(type) {
	case int:
		return t, nil
	case float64:
		return int(t), nil
	default:
		return 0, fmt.Errorf("invalid integer value %v (%T)", v, v)
	}
}
