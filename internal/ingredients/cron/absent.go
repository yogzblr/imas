package cron

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
)

func (c Cron) absent(ctx context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	user := stringParam(c.params, "user")
	identifier := c.identifierFor()
	command := stringParam(c.params, "command")

	lines, err := readUserCrontab(ctx, user)
	if err != nil {
		result.Failed = true
		return result, err
	}

	updated, removed := RemoveEntry(lines, identifier, command)
	if !removed {
		result.Succeeded = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("cron entry %q is already absent", identifier)))
		return result, nil
	}
	if test {
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("cron entry %q would be removed", identifier)))
		return result, nil
	}
	if err := writeUserCrontab(ctx, user, updated); err != nil {
		result.Failed = true
		return result, err
	}
	result.Succeeded = true
	result.Changed = true
	result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("cron entry %q removed", identifier)))
	return result, nil
}
