package cron

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
)

func (c Cron) present(ctx context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	command := stringParam(c.params, "command")
	if command == "" {
		result.Failed = true
		return result, fmt.Errorf("cron entry %s: command must be a non-empty string", c.id)
	}
	user := stringParam(c.params, "user")
	identifier := c.identifierFor()

	newEntry := Entry{
		Minute:     scheduleParam(c.params, "minute"),
		Hour:       scheduleParam(c.params, "hour"),
		DayOfMonth: scheduleParam(c.params, "dayofmonth"),
		Month:      scheduleParam(c.params, "month"),
		DayOfWeek:  scheduleParam(c.params, "dayofweek"),
		Command:    command,
	}

	lines, err := readUserCrontab(ctx, user)
	if err != nil {
		result.Failed = true
		return result, err
	}

	updated, changed := UpsertEntry(lines, identifier, newEntry)
	if !changed {
		result.Succeeded = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("cron entry %q is already present", identifier)))
		return result, nil
	}
	if test {
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("cron entry %q would be added/updated: %s", identifier, FormatEntry(newEntry))))
		return result, nil
	}
	if err := writeUserCrontab(ctx, user, updated); err != nil {
		result.Failed = true
		return result, err
	}
	result.Succeeded = true
	result.Changed = true
	result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("cron entry %q added/updated: %s", identifier, FormatEntry(newEntry))))
	return result, nil
}
