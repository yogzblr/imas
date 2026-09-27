package main

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/api/handlers"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/jobs"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/props"
	"github.com/yogzblr/imas/internal/rbac"
)

// newStorageTestDB migrates and installs the farmer schema the way
// initStorage does (storageModels, then installStorage), against in-memory
// sqlite rather than PXC.
func newStorageTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	sqlDB, _ := gdb.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := gdb.AutoMigrate(storageModels()...); err != nil {
		t.Fatalf("migrating farmer schema: %v", err)
	}
	installStorage(gdb)
	t.Cleanup(func() {
		props.SetDB(nil)
		pki.SetDB(nil)
		rbac.SetDB(nil)
		jobs.SetDB(nil)
		handlers.SetReadinessDB(nil)
		sqlDB.Close()
	})
	return gdb
}

func startTestNATS(t *testing.T) *nats.Conn {
	t.Helper()
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatalf("start test NATS server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server failed to become ready")
	}
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		ns.Shutdown()
		t.Fatalf("connect to test NATS: %v", err)
	}
	t.Cleanup(func() { nc.Close(); ns.Shutdown() })
	return nc
}

func TestStorageModelsIncludeJobStatus(t *testing.T) {
	gdb := newStorageTestDB(t)
	for _, table := range []string{"job_status", "props"} {
		if !gdb.Migrator().HasTable(table) {
			t.Errorf("table %s missing after migrating storageModels()", table)
		}
	}
}

// With the farmer schema installed as initStorage installs it, a cook
// job dispatched to a tenant's sprout, and its events arriving on that
// tenant's connection, land in job_status under that tenant.
func TestInstalledStorageIndexesCookJobs(t *testing.T) {
	gdb := newStorageTestDB(t)
	nc := startTestNATS(t)
	const tenant, sprout, jid = "t_farmer", "web-01", "22222222-2222-2222-2222-222222222222"
	jobs.RegisterNatsConn(tenant, nc)
	t.Cleanup(func() { cook.SetDispatchRecorder(nil) })
	cook.RegisterFarmerNatsConn(tenant, nc)
	t.Cleanup(func() { cook.UnregisterFarmerNatsConn(tenant) })
	// The sprout has no box key on record, so the dispatch is plaintext
	// and a stub can acknowledge it.
	if _, err := nc.Subscribe(cook.CookSubject(sprout), func(m *nats.Msg) {
		var env cook.RecipeEnvelope
		json.Unmarshal(m.Data, &env)
		b, _ := json.Marshal(cook.Ack{Acknowledged: true, JobID: env.JobID})
		m.Respond(b)
	}); err != nil {
		t.Fatalf("subscribing stub sprout: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flushing subscriptions: %v", err)
	}

	if err := cook.SendStepsEvent(tenant, sprout, jid, []cook.Step{{ID: "s1"}}); err != nil {
		t.Fatalf("dispatching: %v", err)
	}
	for _, step := range []cook.StepCompletion{
		{ID: cook.StepID("start-" + jid), CompletionStatus: cook.StepCompleted},
		{ID: "s1", CompletionStatus: cook.StepCompleted},
		{ID: cook.StepID("completed-" + jid), CompletionStatus: cook.StepCompleted},
	} {
		b, _ := json.Marshal(step)
		if err := nc.Publish("imas.cook."+sprout+"."+jid, b); err != nil {
			t.Fatalf("publishing step: %v", err)
		}
	}

	var status string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var rows []struct{ Status string }
		err := gdb.Table("job_status").Select("status").
			Where("tenant_id = ? AND sprout_id = ? AND jid = ?", tenant, sprout, jid).Scan(&rows).Error
		if err != nil {
			t.Fatalf("reading job_status: %v", err)
		}
		if len(rows) == 1 {
			status = rows[0].Status
			if status == jobs.JobIndexStatusSucceeded {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("job_status for %s = %q, want %q", jid, status, jobs.JobIndexStatusSucceeded)
}
