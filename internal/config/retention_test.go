package config

import (
	"strings"
	"testing"
	"time"
)

func retentionWith(env map[string]string, file map[string]any) (FarmerRetention, error) {
	return farmerRetentionFrom(func(k string) string { return env[k] }, func(k string) any { return file[k] })
}

func TestFarmerRetentionDefaults(t *testing.T) {
	for name, tc := range map[string]struct {
		env  map[string]string
		file map[string]any
	}{
		"unset":         {},
		"empty env":     {env: map[string]string{EnvJobLogTTL: "", EnvRecipeAuditRetentionDays: " ", EnvBoxKeyGraceDuration: ""}},
		"zero env":      {env: map[string]string{EnvJobLogTTL: "0", EnvBoxKeyGraceDuration: "0s"}},
		"zero file":     {file: map[string]any{"joblogttl": 0, "boxkeygraceduration": "0"}},
		"jety defaults": {file: map[string]any{"joblogttl": DefaultJobLogTTL, "boxkeygraceduration": DefaultBoxKeyGraceDuration}},
	} {
		r, err := retentionWith(tc.env, tc.file)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.JobLogTTL != 720*time.Hour || r.BoxKeyGraceDuration != 24*time.Hour || r.RecipeAuditRetentionDays != 365 {
			t.Fatalf("%s: %+v, want the defaults (720h, 24h, 365 days)", name, r)
		}
	}
}

func TestFarmerRetentionSet(t *testing.T) {
	r, err := retentionWith(map[string]string{EnvJobLogTTL: "2160h", EnvRecipeAuditRetentionDays: "0", EnvBoxKeyGraceDuration: "1h"},
		map[string]any{"joblogttl": "1h"})
	if err != nil {
		t.Fatal(err)
	}
	if r.JobLogTTL != 2160*time.Hour || r.RecipeAuditRetentionDays != 0 || r.BoxKeyGraceDuration != time.Hour {
		t.Fatalf("%+v: the variables win, and recipe audit 0 means for ever", r)
	}
	r, err = retentionWith(nil, map[string]any{"joblogttl": "48h", "recipeauditretentiondays": 30, "boxkeygraceduration": "15m"})
	if err != nil {
		t.Fatal(err)
	}
	if r.JobLogTTL != 48*time.Hour || r.RecipeAuditRetentionDays != 30 || r.BoxKeyGraceDuration != 15*time.Minute {
		t.Fatalf("config file keys: %+v", r)
	}
}

// A bad value is an error naming the variable or key, never a silent 0
// (which used to turn the job reaper off).
func TestFarmerRetentionRefusesBadValues(t *testing.T) {
	for name, tc := range map[string]struct {
		env  map[string]string
		file map[string]any
		want string
	}{
		"ttl garbage":         {env: map[string]string{EnvJobLogTTL: "30 days"}, want: EnvJobLogTTL},
		"ttl too short":       {env: map[string]string{EnvJobLogTTL: "30m"}, want: EnvJobLogTTL},
		"ttl too long":        {env: map[string]string{EnvJobLogTTL: "87601h"}, want: EnvJobLogTTL},
		"ttl negative":        {env: map[string]string{EnvJobLogTTL: "-1h"}, want: EnvJobLogTTL},
		"ttl file no unit":    {file: map[string]any{"joblogttl": 30}, want: "joblogttl"},
		"ttl file garbage":    {file: map[string]any{"joblogttl": "forever"}, want: "joblogttl"},
		"grace too short":     {env: map[string]string{EnvBoxKeyGraceDuration: "5m"}, want: EnvBoxKeyGraceDuration},
		"grace too long":      {file: map[string]any{"boxkeygraceduration": "721h"}, want: "boxkeygraceduration"},
		"audit garbage":       {env: map[string]string{EnvRecipeAuditRetentionDays: "1y"}, want: EnvRecipeAuditRetentionDays},
		"audit negative":      {env: map[string]string{EnvRecipeAuditRetentionDays: "-1"}, want: EnvRecipeAuditRetentionDays},
		"audit too long":      {env: map[string]string{EnvRecipeAuditRetentionDays: "3651"}, want: EnvRecipeAuditRetentionDays},
		"audit file fraction": {file: map[string]any{"recipeauditretentiondays": 1.5}, want: "recipeauditretentiondays"},
	} {
		_, err := retentionWith(tc.env, tc.file)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want one naming %s", name, err, tc.want)
		}
	}
}
