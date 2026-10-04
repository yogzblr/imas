package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/taigrr/jety"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
	"github.com/yogzblr/imas/internal/rbac"
)

// setupRotateKey stands up a farmer side (users store, tenant key mock)
// and a CLI user with a registered box key, and returns the user ID.
func setupRotateKey(t *testing.T) string {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(append(pki.Models(), rbac.Models()...)...); err != nil {
		t.Fatal(err)
	}
	pki.SetDB(gdb)
	rbac.SetDB(gdb)
	t.Cleanup(func() { pki.SetDB(nil); rbac.SetDB(nil) })
	tenantboxtest.Start(t)
	pki.InvalidateTenantBoxKeys("t_1")
	t.Cleanup(func() { pki.InvalidateTenantBoxKeys("t_1") })

	rs := rbac.NewRoleStore()
	if err := rs.Register(&rbac.Role{Name: "admin", Rules: []rbac.Rule{{Action: rbac.ActionAdmin, Scope: "*"}}}); err != nil {
		t.Fatal(err)
	}
	urm := rbac.NewUserRoleMap()
	auth.SetPolicy(rs, urm, nil)
	t.Cleanup(func() { auth.SetPolicy(nil, nil, nil) })

	kp, _ := nkeys.CreateAccount()
	seed, _ := kp.Seed()
	user, _ := kp.PublicKey()
	urm.Set(user, "admin")
	tk, err := pki.GetTenantX25519PublicKey("t_1")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "cli-box.key")
	jety.Set("privkey", string(seed))
	jety.Set(pki.CLIBoxPrivFileKey, keyFile)
	jety.Set(pki.CLITenantBoxPubKey, tk)
	jety.Set(pki.CLITenantIDKey, "t_1")
	t.Cleanup(func() {
		for _, k := range []string{"privkey", pki.CLIBoxPrivFileKey, pki.CLITenantBoxPubKey, pki.CLITenantIDKey} {
			jety.Set(k, "")
		}
	})
	pub, err := pki.GenerateCLIBoxKey(keyFile, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.RegisterCLIBoxKey("t_1", user, pub); err != nil {
		t.Fatal(err)
	}
	return user
}

// farmerRotateKey answers rotations the way farmer will at rollout step
// 4: open under the user's registered key, record the new key, reply
// sealed (which goes to the new, now active, key).
func farmerRotateKey(t *testing.T, nc *nats.Conn, answer func(m *nats.Msg) *nats.Msg) {
	t.Helper()
	sub, err := nc.Subscribe(pki.CLIAPISubjectPrefix+pki.MethodAuthRotateKey, func(m *nats.Msg) {
		if answer != nil {
			_ = m.RespondMsg(answer(m))
			return
		}
		user := m.Header.Get(payloadbox.PrincipalHeader)
		opened, body, under, err := pki.OpenFromCLI("t_1", user, payloadbox.PurposeCLIUserKeySubmit, pki.MethodAuthRotateKey, m.Subject, m.Data)
		if err != nil {
			t.Errorf("farmer: %v", err)
			return
		}
		if _, err := pki.RecordCLIBoxKeySubmission("t_1", user, under, body); err != nil {
			t.Errorf("farmer: record: %v", err)
			return
		}
		reply, err := pki.SealToCLI("t_1", user, payloadbox.Reply{
			Purpose: payloadbox.PurposeCLIReply, ReplyTo: opened.ID, Method: pki.MethodAuthRotateKey, Subject: m.Subject,
		})
		if err != nil {
			t.Errorf("farmer: seal: %v", err)
			return
		}
		resp := nats.NewMsg(m.Reply)
		resp.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
		resp.Data = reply
		_ = m.RespondMsg(resp)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sub.Unsubscribe() })
}

func TestRotateCLIBoxKey(t *testing.T) {
	user := setupRotateKey(t)
	_, nc := startTestNATSServer(t)
	before, _ := pki.CLIBoxPub()

	// Nothing serves sealed requests yet: the key stays pending.
	if _, err := rotateCLIBoxKey(nc, time.Second); !errors.Is(err, errSealedNotServed) {
		t.Fatalf("no responders: %v", err)
	}
	if cur, _ := pki.CLIBoxPub(); cur != before {
		t.Fatal("the key changed with nothing answering")
	}
	if _, err := os.Stat(jety.GetString(pki.CLIBoxPrivFileKey) + ".next"); err != nil {
		t.Fatalf("pending key: %v", err)
	}

	farmerRotateKey(t, nc, nil)
	newPub, err := rotateCLIBoxKey(nc, 5*time.Second)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if cur, _ := pki.CLIBoxPub(); cur != newPub || cur == before {
		t.Fatalf("current key %s, want the new %s", cur, newPub)
	}
	if active, grace, err := auth.ValidCLIBoxKeys("t_1", user); err != nil || active != newPub || len(grace) != 1 || grace[0] != before {
		t.Fatalf("farmer's view: %s %v %v", active, grace, err)
	}
}

func TestRotateCLIBoxKeyRefusedOrUnsealed(t *testing.T) {
	setupRotateKey(t)
	_, nc := startTestNATSServer(t)
	before, _ := pki.CLIBoxPub()
	answer := func(code string) func(m *nats.Msg) *nats.Msg {
		return func(m *nats.Msg) *nats.Msg {
			resp := nats.NewMsg(m.Reply)
			if code != "" {
				resp.Header.Set(payloadbox.ErrorHeader, code)
			} else {
				resp.Data = []byte(`{"result":{"ok":true}}`)
			}
			return resp
		}
	}
	farmerRotateKey(t, nc, answer(payloadbox.ErrorCodeOpenFailed))
	if _, err := rotateCLIBoxKey(nc, 5*time.Second); err == nil {
		t.Fatal("a refusal was taken for success")
	}
	if cur, _ := pki.CLIBoxPub(); cur != before {
		t.Fatal("promoted on a refusal")
	}
	_, nc2 := startTestNATSServer(t)
	farmerRotateKey(t, nc2, answer(""))
	if _, err := rotateCLIBoxKey(nc2, 5*time.Second); err == nil {
		t.Fatal("a plaintext answer was accepted")
	}
	if cur, _ := pki.CLIBoxPub(); cur != before {
		t.Fatal("promoted on a plaintext answer")
	}
}
