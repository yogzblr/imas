package cook

// Security review 2026-10 (SEC.3b): replay after a restart (M2), handled
// jobs refused on the push path (M2), tenant binding (H3), and no opened
// envelope reaching a log sink (H4).

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// captureDispatch sends job jobID to e's sprout and returns the sealed
// dispatch as the bus saw it.
func captureDispatch(t *testing.T, e *sealedCookEnv, jobID string) *nats.Msg {
	t.Helper()
	spy := spyOnCookBus(t, e, CookSubject(e.sproutID))
	if err := SendStepsEvent(e.tenant, e.sproutID, jobID, secretSteps()); err != nil {
		t.Fatal(err)
	}
	for _, m := range spy.waitFor(t, 1) {
		if m.Subject == CookSubject(e.sproutID) {
			return m
		}
	}
	t.Fatal("dispatch not seen on the bus")
	return nil
}

func resend(t *testing.T, e *sealedCookEnv, captured *nats.Msg) *nats.Msg {
	t.Helper()
	replay := nats.NewMsg(captured.Subject)
	replay.Header = captured.Header
	replay.Data = captured.Data
	reply, err := e.farmer.RequestMsg(replay, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

// M2: a captured sealed dispatch replayed after the sprout restarts is
// refused, and the job is cooked once.
func TestSealedCook_ReplayAfterRestartIsRefused(t *testing.T) {
	e := setupSealedCook(t, "t_cook_restart")
	t.Cleanup(pki.ForgetSproutReplayGuard)
	captured := captureDispatch(t, e, "job-restart")
	pki.ForgetSproutReplayGuard() // the sprout restarts
	reply := resend(t, e, captured)
	if code := reply.Header.Get(payloadbox.ErrorHeader); code != payloadbox.ErrorCodeOpenFailed {
		t.Errorf("refusal code %q, want %q", code, payloadbox.ErrorCodeOpenFailed)
	}
	if got := e.cookedJobs(); !slices.Equal(got, []string{"job-restart"}) {
		t.Errorf("sprout accepted %v, want the job once", got)
	}
}

// M2: RespondCook refuses a job already in the handled jobs file. Even
// with the replay guard's state lost entirely (its file deleted), the
// replayed dispatch opens but is not cooked; and a fresh dispatch reusing
// a handled job ID isn't either.
func TestSealedCook_HandledJobIsNotCookedAgain(t *testing.T) {
	e := setupSealedCook(t, "t_cook_handled")
	t.Cleanup(pki.ForgetSproutReplayGuard)
	captured := captureDispatch(t, e, "job-handled")

	pki.ForgetSproutReplayGuard()
	if err := os.Remove(pkiReplayGuardFile(t)); err != nil {
		t.Fatal(err)
	}
	reply := resend(t, e, captured)
	if code := reply.Header.Get(payloadbox.ErrorHeader); code != "" {
		t.Fatalf("with the replay guard gone the dispatch should open, got refusal %q", code)
	}
	m, err := pki.OpenFromSprout(e.tenant, e.sproutID, payloadbox.PurposeCookResponse, reply.Data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(m.Body), `"Acknowledged":false`) {
		t.Errorf("Ack for a handled job = %s, want not acknowledged", m.Body)
	}

	// A new dispatch (fresh message ID) naming the handled job.
	if err := SendStepsEvent(e.tenant, e.sproutID, "job-handled", secretSteps()); err == nil {
		t.Error("farmer's dispatch of a handled job was acknowledged")
	}
	if got := e.cookedJobs(); !slices.Equal(got, []string{"job-handled"}) {
		t.Errorf("sprout accepted %v, want the job once", got)
	}
}

// pkiReplayGuardFile is where pki persists the sprout's replay guard
// (next to its box private key).
func pkiReplayGuardFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(filepath.Dir(config.SproutBoxPrivFile), "payload-replay.json")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("replay guard file: %v", err)
	}
	return p
}

// H3: a dispatch sealed under the sprout's own keys but naming another
// tenant is refused and not cooked.
func TestSealedCook_AnotherTenantsDispatchRefusedUnderSharedKey(t *testing.T) {
	e := setupSealedCook(t, "t_cook_shared")
	active, _, err := pki.ValidSproutBoxKeys(e.tenant, e.sproutID)
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := pki.DecodeBoxPubKey(active)
	tenantKeys, err := pki.TenantBoxKeys(e.tenant)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := payloadbox.NewMessage(payloadbox.PurposeCookRequest, "t_cook_other", e.sproutID, "",
		RecipeEnvelope{JobID: "job-other-tenant", Steps: secretSteps()})
	if err != nil {
		t.Fatal(err)
	}
	data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: sp, Priv: tenantKeys[0].Priv}})
	if err != nil {
		t.Fatal(err)
	}
	req := nats.NewMsg(CookSubject(e.sproutID))
	req.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	req.Data = data
	reply, err := e.farmer.RequestMsg(req, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code := reply.Header.Get(payloadbox.ErrorHeader); code != payloadbox.ErrorCodeOpenFailed {
		t.Errorf("refusal code %q, want %q", code, payloadbox.ErrorCodeOpenFailed)
	}
	if got := e.cookedJobs(); len(got) != 0 {
		t.Errorf("sprout accepted %v from another tenant", got)
	}
}

// logSinks captures every log sink at every level: the terminal logger
// (at Trace) and the NATS backend (minimum Trace, so its filter can't
// hide anything).
type logSinks struct {
	mu       sync.Mutex
	terminal bytes.Buffer
	bus      [][]byte
}

func (s *logSinks) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminal.Write(p)
}

// hits returns "<sink>: <marker>" for every marker found in either sink.
func (s *logSinks) hits(markers ...string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, m := range markers {
		if bytes.Contains(s.terminal.Bytes(), []byte(m)) {
			out = append(out, "terminal: "+m)
		}
		for _, b := range s.bus {
			if bytes.Contains(b, []byte(m)) {
				out = append(out, "NATS: "+m)
				break
			}
		}
	}
	return out
}

// H4: nothing from an opened cook envelope (step IDs aside, its rendered
// properties) reaches any log sink, including the NATS one, through the
// sprout's whole path: RespondCook opening and acknowledging it, and
// CookRecipeEnvelope cooking it. A refused dispatch logs nothing of it
// either.
func TestSealedCook_NoOpenedEnvelopeReachesALogSink(t *testing.T) {
	e := setupSealedCook(t, "t_cook_logs")
	sinks := &logSinks{}
	log.SetOutput(sinks)
	log.SetLogLevel(log.LTrace)
	log.SetNATSMinLevel(log.LTrace)
	t.Cleanup(func() {
		log.DetachNATS()
		log.SetOutput(nil)
		log.SetLogLevel(log.LDebug)
		log.SetNATSMinLevel(log.DefaultNATSMinLevel)
	})
	if _, err := e.farmer.Subscribe("imas.logs.>", func(m *nats.Msg) {
		sinks.mu.Lock()
		sinks.bus = append(sinks.bus, m.Data)
		sinks.mu.Unlock()
	}); err != nil {
		t.Fatal(err)
	}
	e.farmer.Flush()
	if err := log.UseNATSConn(e.sprout, "imas.logs.sprouts."+e.sproutID); err != nil {
		t.Fatal(err)
	}

	// Cook what the sprout accepted, as cmd/sprout/nats.go does, with a
	// stand-in ingredient.
	RegisterNatsConn(e.sprout)
	origCooker, origJobLogDir := NewRecipeCooker, config.JobLogDir
	config.JobLogDir = t.TempDir()
	t.Cleanup(func() { NewRecipeCooker, config.JobLogDir = origCooker, origJobLogDir })
	NewRecipeCooker = func(StepID, Ingredient, string, map[string]interface{}) (RecipeCooker, error) {
		return &mockRecipeCooker{applyResult: Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{SimpleNote("applied")}}}, nil
	}

	captured := captureDispatch(t, e, "job-logs")
	e.mu.Lock()
	accepted := slices.Clone(e.cooked)
	e.mu.Unlock()
	if len(accepted) != 1 {
		t.Fatalf("sprout accepted %d dispatches, want 1", len(accepted))
	}
	if err := CookRecipeEnvelope(accepted[0]); err != nil {
		t.Fatalf("CookRecipeEnvelope: %v", err)
	}
	resend(t, e, captured) // refused as a replay
	log.Flush()
	e.sprout.Flush()
	time.Sleep(200 * time.Millisecond) // let the bus deliver the shipped entries

	if hits := sinks.hits("secret-recipe-3a9f", "db_password", "/etc/app.conf"); len(hits) > 0 {
		t.Fatalf("opened envelope content reached log sinks: %v", hits)
	}
	if hits := sinks.hits("job-logs"); len(hits) < 2 {
		t.Fatalf("control: the job ID reached only %v, want both sinks, so the test proves nothing", hits)
	}
	sinks.mu.Lock()
	shipped := len(sinks.bus)
	sinks.mu.Unlock()
	if shipped == 0 {
		t.Fatal("control: nothing reached the NATS log sink, so the test proves nothing")
	}
}
