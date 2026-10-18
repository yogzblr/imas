package cmd

import (
	"errors"
	"testing"

	"github.com/yogzblr/imas/internal/cook"
)

func TestCookFailed(t *testing.T) {
	const jid = "j1"
	start := cook.StepCompletion{ID: "start-j1", CompletionStatus: cook.StepCompleted}
	done := cook.StepCompletion{ID: "completed-j1", CompletionStatus: cook.StepCompleted}
	ok := cook.StepCompletion{ID: "a", CompletionStatus: cook.StepCompleted}
	skipped := cook.StepCompletion{ID: "b", CompletionStatus: cook.StepSkipped}
	failed := cook.StepCompletion{ID: "c", CompletionStatus: cook.StepFailed}
	errored := cook.StepCompletion{ID: "d", CompletionStatus: cook.StepCompleted, Error: errors.New("boom")}
	otherDone := cook.StepCompletion{ID: "completed-j2", CompletionStatus: cook.StepCompleted}

	tests := []struct {
		name     string
		targeted []string
		steps    map[string][]cook.StepCompletion
		timedOut bool
		want     bool
	}{
		{"all succeeded", []string{"s1", "s2"}, map[string][]cook.StepCompletion{
			"s1": {start, ok, done}, "s2": {start, ok, skipped, done}}, false, false},
		{"no targets no steps", nil, nil, false, false},
		{"step failed", []string{"s1", "s2"}, map[string][]cook.StepCompletion{
			"s1": {start, ok, done}, "s2": {start, failed, done}}, false, true},
		{"step carries error", []string{"s1"}, map[string][]cook.StepCompletion{
			"s1": {start, errored, done}}, false, true},
		{"timed out", []string{"s1"}, map[string][]cook.StepCompletion{
			"s1": {start, ok, done}}, true, true},
		{"target never reported", []string{"s1", "s2"}, map[string][]cook.StepCompletion{
			"s1": {start, ok, done}}, false, true},
		{"target never completed", []string{"s1"}, map[string][]cook.StepCompletion{
			"s1": {start, ok}}, false, true},
		{"completion step of another job", []string{"s1"}, map[string][]cook.StepCompletion{
			"s1": {start, ok, otherDone}}, false, true},
		{"untargeted sprout failed", []string{"s1"}, map[string][]cook.StepCompletion{
			"s1": {start, done}, "s9": {failed}}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cookFailed(jid, tt.targeted, tt.steps, tt.timedOut); got != tt.want {
				t.Errorf("cookFailed() = %v, want %v", got, tt.want)
			}
		})
	}
}
