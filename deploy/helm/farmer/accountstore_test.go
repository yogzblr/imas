package farmerchart

import (
	"slices"
	"testing"
)

// The accounts bucket (docs/briefs/P21-slice2-bus-loader.md §4.6): farmer
// gets IMAS_ACCOUNTS_* from accountStore, with its own write credential,
// and IMAS_BUS_EXPECTED_NODES from bus.expectedNodes.
func TestAccountStoreEnvRendered(t *testing.T) {
	accountsEnv := []string{"IMAS_ACCOUNTS_S3_BUCKET", "IMAS_ACCOUNTS_S3_ENDPOINT", "IMAS_ACCOUNTS_S3_USE_SSL",
		"IMAS_ACCOUNTS_S3_ACCESS_KEY_ID", "IMAS_ACCOUNTS_S3_SECRET_ACCESS_KEY", "IMAS_ACCOUNTS_EVENT_SUBJECT", "IMAS_BUS_EXPECTED_NODES"}

	t.Run("no endpoint: off", func(t *testing.T) {
		env := envMap(container(t, farmerDeploy(t, mustRender(t)), "farmer"))
		for _, k := range accountsEnv {
			if _, ok := env[k]; ok {
				t.Errorf("%s rendered without an object store endpoint", k)
			}
		}
	})

	objectStore := []string{"--set", "objectStore.endpoint=s3.imas-core.svc:9000",
		"--set", "objectStore.credentialsSecret=imas-farmer-s3"}

	t.Run("defaults on the object store endpoint", func(t *testing.T) {
		c := container(t, farmerDeploy(t, mustRender(t, objectStore...)), "farmer")
		env, vals := envMap(c), envValues(c)
		if vals["IMAS_ACCOUNTS_S3_BUCKET"] != "imas-accounts" || vals["IMAS_ACCOUNTS_EVENT_SUBJECT"] != "imas.bus.accounts.changed" {
			t.Errorf("bucket %q, subject %q", vals["IMAS_ACCOUNTS_S3_BUCKET"], vals["IMAS_ACCOUNTS_EVENT_SUBJECT"])
		}
		// Endpoint and TLS fall back to IMAS_S3_* inside farmer.
		for _, k := range []string{"IMAS_ACCOUNTS_S3_ENDPOINT", "IMAS_ACCOUNTS_S3_USE_SSL", "IMAS_BUS_EXPECTED_NODES"} {
			if _, ok := env[k]; ok {
				t.Errorf("%s rendered with its default", k)
			}
		}
		for k, key := range map[string]string{
			"IMAS_ACCOUNTS_S3_ACCESS_KEY_ID":     "access-key-id",
			"IMAS_ACCOUNTS_S3_SECRET_ACCESS_KEY": "secret-access-key",
		} {
			ref := get(env[k], "valueFrom", "secretKeyRef")
			if get(ref, "name") != "imas-farmer-accounts-writer" || get(ref, "key") != key {
				t.Errorf("%s from %v, want Secret imas-farmer-accounts-writer key %s", k, ref, key)
			}
		}
	})

	t.Run("own endpoint, TLS and expected nodes", func(t *testing.T) {
		docs := mustRender(t, append(slices.Clone(objectStore),
			"--set", "accountStore.endpoint=accounts.imas-core.svc:9443",
			"--set", "accountStore.useSSL=false",
			"--set", "accountStore.eventSubject=imas.test.changed",
			"--set", "bus.expectedNodes=3")...)
		vals := envValues(container(t, farmerDeploy(t, docs), "farmer"))
		for k, want := range map[string]string{
			"IMAS_ACCOUNTS_S3_ENDPOINT":   "accounts.imas-core.svc:9443",
			"IMAS_ACCOUNTS_S3_USE_SSL":    "false",
			"IMAS_ACCOUNTS_EVENT_SUBJECT": "imas.test.changed",
			"IMAS_BUS_EXPECTED_NODES":     "3",
		} {
			if vals[k] != want {
				t.Errorf("%s = %q, want %q", k, vals[k], want)
			}
		}
		if ports := egressPorts(find(t, docs, "NetworkPolicy", "t-farmer")); !slices.Contains(ports, 9443) || !slices.Contains(ports, 9000) {
			t.Errorf("farmer egress ports %v, want the object store's 9000 and the accounts bucket's 9443", ports)
		}
	})

	t.Run("validation", func(t *testing.T) {
		mustFail(t, "must not be objectStore.credentialsSecret", append(slices.Clone(objectStore),
			"--set", "accountStore.credentialsSecret=imas-farmer-s3")...)
		mustFail(t, "accountStore.credentialsSecret is required", append(slices.Clone(objectStore),
			"--set", "accountStore.credentialsSecret=")...)
		for _, b := range []string{"bucket", "jobBucket", "sproutJWTBucket"} {
			mustFail(t, "accountStore.bucket", append(slices.Clone(objectStore),
				"--set", "objectStore."+b+"=imas-accounts")...)
		}
		mustFail(t, "bus.expectedNodes must be a whole number", "--set", "bus.expectedNodes=-1")
		mustFail(t, "accountStore.useSSL", append(slices.Clone(objectStore), "--set-string", "accountStore.useSSL=yes")...)
	})
}
