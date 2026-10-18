package serve

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/cook"
)

func newTestHub() *logHub {
	return &logHub{
		clients: make(map[*logClient]struct{}),
		recent:  make([]LogEntry, 0, maxRecentLogs),
	}
}

func TestMatchesFilter(t *testing.T) {
	tests := []struct {
		name   string
		entry  LogEntry
		level  string
		source string
		want   bool
	}{
		{
			name:   "no filters",
			entry:  LogEntry{Level: "debug", Source: "sprout"},
			level:  "",
			source: "",
			want:   true,
		},
		{
			name:   "level filter passes",
			entry:  LogEntry{Level: "error", Source: "sprout"},
			level:  "warn",
			source: "",
			want:   true,
		},
		{
			name:   "level filter blocks",
			entry:  LogEntry{Level: "debug", Source: "sprout"},
			level:  "info",
			source: "",
			want:   false,
		},
		{
			name:   "source filter passes",
			entry:  LogEntry{Level: "info", Source: "farmer"},
			level:  "",
			source: "farmer",
			want:   true,
		},
		{
			name:   "source filter blocks",
			entry:  LogEntry{Level: "info", Source: "sprout"},
			level:  "",
			source: "farmer",
			want:   false,
		},
		{
			name:   "both filters pass",
			entry:  LogEntry{Level: "warn", Source: "sprout"},
			level:  "info",
			source: "sprout",
			want:   true,
		},
		{
			name:   "level passes source blocks",
			entry:  LogEntry{Level: "error", Source: "farmer"},
			level:  "warn",
			source: "sprout",
			want:   false,
		},
		{
			name:   "exact level match",
			entry:  LogEntry{Level: "info", Source: "sprout"},
			level:  "info",
			source: "",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesFilter(tt.entry, tt.level, tt.source)
			if got != tt.want {
				t.Errorf("matchesFilter(%+v, %q, %q) = %v, want %v",
					tt.entry, tt.level, tt.source, got, tt.want)
			}
		})
	}
}

func TestLogHubStoreAndGetRecent(t *testing.T) {
	h := newTestHub()

	entries := []LogEntry{
		{Timestamp: "2026-01-01T00:00:00Z", Level: "debug", Source: "sprout", SourceID: "s1", Message: "debug msg"},
		{Timestamp: "2026-01-01T00:00:01Z", Level: "info", Source: "sprout", SourceID: "s1", Message: "info msg"},
		{Timestamp: "2026-01-01T00:00:02Z", Level: "warn", Source: "farmer", Message: "warn msg"},
		{Timestamp: "2026-01-01T00:00:03Z", Level: "error", Source: "sprout", SourceID: "s2", Message: "error msg"},
	}

	for _, e := range entries {
		h.storeRecent(e)
	}

	// Get all
	all := h.getRecent("", "", 0)
	if len(all) != 4 {
		t.Errorf("getRecent (all) = %d entries, want 4", len(all))
	}

	// Filter by level
	warns := h.getRecent("warn", "", 0)
	if len(warns) != 2 {
		t.Errorf("getRecent (warn+) = %d entries, want 2", len(warns))
	}

	// Filter by source
	farmers := h.getRecent("", "farmer", 0)
	if len(farmers) != 1 {
		t.Errorf("getRecent (farmer) = %d entries, want 1", len(farmers))
	}

	// Limit
	limited := h.getRecent("", "", 2)
	if len(limited) != 2 {
		t.Errorf("getRecent (limit 2) = %d entries, want 2", len(limited))
	}
	// Should be the most recent 2
	if limited[0].Level != "warn" || limited[1].Level != "error" {
		t.Errorf("getRecent (limit 2) returned wrong entries: %+v", limited)
	}
}

func TestLogHubRecentRingBuffer(t *testing.T) {
	h := newTestHub()

	// Store more than maxRecentLogs entries
	for i := 0; i < maxRecentLogs+50; i++ {
		h.storeRecent(LogEntry{
			Timestamp: "2026-01-01T00:00:00Z",
			Level:     "info",
			Source:    "sprout",
			Message:   "msg",
		})
	}

	all := h.getRecent("", "", 0)
	if len(all) != maxRecentLogs {
		t.Errorf("ring buffer size = %d, want %d", len(all), maxRecentLogs)
	}
}

func TestHandleRecentLogsEndpoint(t *testing.T) {
	h := newTestHub()
	h.storeRecent(LogEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		Level:     "info",
		Source:    "sprout",
		SourceID:  "test-sprout",
		Message:   "test message",
	})

	handler := handleRecentLogsWithHub(h)
	req := httptest.NewRequest("GET", "/api/v1/logs?level=info&source=sprout&limit=10", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp struct {
		Logs []LogEntry `json:"logs"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Logs) != 1 {
		t.Fatalf("logs count = %d, want 1", len(resp.Logs))
	}
	if resp.Logs[0].Message != "test message" {
		t.Errorf("message = %q, want %q", resp.Logs[0].Message, "test message")
	}
}

func TestWebSocketLogStream(t *testing.T) {
	h := newTestHub()
	handler := handleLogStreamWithHub(h)

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()

	// Wait for client to be registered
	time.Sleep(50 * time.Millisecond)

	entry := LogEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		Level:     "info",
		Source:    "sprout",
		SourceID:  "test-sprout",
		Message:   "streamed message",
	}
	h.broadcast(entry)

	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, data, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var received LogEntry
	if err := json.Unmarshal(data, &received); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if received.Message != "streamed message" {
		t.Errorf("message = %q, want %q", received.Message, "streamed message")
	}
}

func TestWebSocketLevelFilter(t *testing.T) {
	h := newTestHub()
	handler := handleLogStreamWithHub(h)

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?level=warn"
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()

	time.Sleep(50 * time.Millisecond)

	// Send a debug entry (should be filtered out)
	h.broadcast(LogEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		Level:     "debug",
		Source:    "sprout",
		Message:   "debug msg",
	})

	// Send an error entry (should pass)
	h.broadcast(LogEntry{
		Timestamp: "2026-01-01T00:00:01Z",
		Level:     "error",
		Source:    "sprout",
		Message:   "error msg",
	})

	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, data, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var received LogEntry
	if err := json.Unmarshal(data, &received); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if received.Message != "error msg" {
		t.Errorf("got %q, want %q (debug should have been filtered)", received.Message, "error msg")
	}
}

func TestWebSocketSourceFilter(t *testing.T) {
	h := newTestHub()
	handler := handleLogStreamWithHub(h)

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?source=farmer"
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer ws.Close()

	time.Sleep(50 * time.Millisecond)

	// Send sprout entry (should be filtered out)
	h.broadcast(LogEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		Level:     "info",
		Source:    "sprout",
		Message:   "sprout msg",
	})

	// Send farmer entry (should pass)
	h.broadcast(LogEntry{
		Timestamp: "2026-01-01T00:00:01Z",
		Level:     "info",
		Source:    "farmer",
		Message:   "farmer msg",
	})

	ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, data, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var received LogEntry
	if err := json.Unmarshal(data, &received); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if received.Message != "farmer msg" {
		t.Errorf("got %q, want %q", received.Message, "farmer msg")
	}
}

func TestCookEntry_ChangesMade(t *testing.T) {
	var step cook.StepCompletion
	if err := json.Unmarshal([]byte(`{
		"id": "install-nginx",
		"completionStatus": 2,
		"changesMade": true,
		"changes": ["installed nginx 1.25"],
		"started": "2026-01-01T00:00:00Z",
		"duration": 5000000000
	}`), &step); err != nil {
		t.Fatal(err)
	}
	entry := cookEntry(cook.FollowedStepEvent{SproutID: "sprout-1", JobID: "jid-001", EventID: "e1", Step: step})
	if entry.Source != "sprout" {
		t.Errorf("expected source 'sprout', got %q", entry.Source)
	}
	if entry.SourceID != "sprout-1" {
		t.Errorf("expected sourceID 'sprout-1', got %q", entry.SourceID)
	}
	if entry.Level != "info" {
		t.Errorf("expected level 'info' for changes-made step, got %q", entry.Level)
	}
	if !strings.Contains(entry.Message, "jid-001") {
		t.Errorf("expected message to contain jid, got %q", entry.Message)
	}
	if !strings.Contains(entry.Message, "completed") {
		t.Errorf("expected message to contain 'completed', got %q", entry.Message)
	}
}

func TestCookEntry_Levels(t *testing.T) {
	for _, c := range []struct {
		step cook.StepCompletion
		want string
	}{
		{cook.StepCompletion{ID: "bad", CompletionStatus: cook.StepFailed, Error: fmt.Errorf("exit 1")}, "error"},
		{cook.StepCompletion{ID: "noop", CompletionStatus: cook.StepCompleted}, "debug"},
	} {
		if got := cookEntry(cook.FollowedStepEvent{SproutID: "s", JobID: "j", Step: c.step}).Level; got != c.want {
			t.Errorf("%s: level %q, want %q", c.step.ID, got, c.want)
		}
	}
}

// The hub reads step events only from its follow (farmer's sealed leg),
// drops the duplicates two overlapping follows deliver, renews the
// follow, and retries one farmer refused.
func TestLogHubFollow(t *testing.T) {
	type stream struct {
		events  chan cook.FollowedStepEvent
		stopped chan struct{}
	}
	streams := make(chan *stream, 8)
	calls := 0
	origFollow, origRenew, origRetry := followJobs, followRenewAfter, followRetryAfter
	t.Cleanup(func() { followJobs, followRenewAfter, followRetryAfter = origFollow, origRenew, origRetry })
	followRenewAfter, followRetryAfter = 50*time.Millisecond, 10*time.Millisecond
	followJobs = func(*nats.Conn) (<-chan cook.FollowedStepEvent, func(), error) {
		calls++
		if calls == 1 {
			return nil, nil, fmt.Errorf("farmer refused")
		}
		s := &stream{events: make(chan cook.FollowedStepEvent, 8), stopped: make(chan struct{})}
		streams <- s
		var once bool
		return s.events, func() {
			if !once {
				once = true
				close(s.stopped)
				close(s.events)
			}
		}, nil
	}
	h := newTestHub()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { h.follow(nil, stop); close(done) }()

	first := <-streams
	ev := cook.FollowedStepEvent{SproutID: "web-01", JobID: "j1", EventID: "e1", Step: cook.StepCompletion{ID: "s1", ChangesMade: true}}
	first.events <- ev
	second := <-streams // the renewal, which overlaps the first
	second.events <- ev // the same event again, through the overlap
	second.events <- cook.FollowedStepEvent{SproutID: "web-01", JobID: "j1", EventID: "e2", Step: cook.StepCompletion{ID: "s2"}}
	select {
	case <-first.stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("the first follow was not stopped after its renewal")
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(h.getRecent("", "", 0)) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	<-done
	got := h.getRecent("", "", 0)
	if len(got) != 2 {
		t.Fatalf("recent entries %v, want 2 (the duplicate dropped)", got)
	}
}

func TestFormatStepMessage_AllStatuses(t *testing.T) {
	tests := []struct {
		name   string
		step   cook.StepCompletion
		jid    string
		wantIn string
	}{
		{
			"not started",
			cook.StepCompletion{ID: "step-1", CompletionStatus: cook.StepNotStarted},
			"j1",
			"not started",
		},
		{
			"in progress",
			cook.StepCompletion{ID: "step-2", CompletionStatus: cook.StepInProgress},
			"j2",
			"in progress",
		},
		{
			"completed",
			cook.StepCompletion{ID: "step-3", CompletionStatus: cook.StepCompleted},
			"j3",
			"completed",
		},
		{
			"failed",
			cook.StepCompletion{ID: "step-4", CompletionStatus: cook.StepFailed},
			"j4",
			"failed",
		},
		{
			"skipped",
			cook.StepCompletion{ID: "step-5", CompletionStatus: cook.StepSkipped},
			"j5",
			"skipped",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := formatStepMessage(tt.step, tt.jid)
			if !strings.Contains(msg, tt.wantIn) {
				t.Errorf("formatStepMessage() = %q, want substring %q", msg, tt.wantIn)
			}
			if !strings.Contains(msg, tt.jid) {
				t.Errorf("formatStepMessage() = %q, should contain jid %q", msg, tt.jid)
			}
		})
	}
}

func TestFormatStepMessage_WithError(t *testing.T) {
	step := cook.StepCompletion{
		ID:               "step-err",
		CompletionStatus: cook.StepFailed,
		Error:            fmt.Errorf("disk full"),
	}
	msg := formatStepMessage(step, "jid-err")
	if !strings.Contains(msg, "disk full") {
		t.Errorf("expected error message in output, got %q", msg)
	}
}

func TestFormatStepMessage_WithChanges(t *testing.T) {
	step := cook.StepCompletion{
		ID:               "step-chg",
		CompletionStatus: cook.StepCompleted,
		ChangesMade:      true,
		Changes:          []string{"installed pkg", "created dir", "wrote config"},
	}
	msg := formatStepMessage(step, "jid-chg")
	if !strings.Contains(msg, "changes:") {
		t.Errorf("expected 'changes:' in output, got %q", msg)
	}
	if !strings.Contains(msg, "installed pkg") {
		t.Errorf("expected change detail in output, got %q", msg)
	}
}

func TestFormatStepMessage_WithManyChanges(t *testing.T) {
	step := cook.StepCompletion{
		ID:               "step-many",
		CompletionStatus: cook.StepCompleted,
		ChangesMade:      true,
		Changes:          []string{"a", "b", "c", "d", "e", "f"},
	}
	msg := formatStepMessage(step, "jid-many")
	if !strings.Contains(msg, "...") {
		t.Errorf("expected truncation '...' for >5 changes, got %q", msg)
	}
}

func TestFormatStepMessage_WithDuration(t *testing.T) {
	step := cook.StepCompletion{
		ID:               "step-dur",
		CompletionStatus: cook.StepCompleted,
		Duration:         3 * time.Second,
	}
	msg := formatStepMessage(step, "jid-dur")
	if !strings.Contains(msg, "3s") {
		t.Errorf("expected duration in output, got %q", msg)
	}
}

func TestHandleRecentLogsDefaultLimit(t *testing.T) {
	h := newTestHub()
	// Add more entries than default limit
	for i := 0; i < 150; i++ {
		h.storeRecent(LogEntry{
			Timestamp: "2026-01-01T00:00:00Z",
			Level:     "info",
			Source:    "sprout",
			Message:   "msg",
		})
	}

	handler := handleRecentLogsWithHub(h)
	req := httptest.NewRequest("GET", "/api/v1/logs", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	var resp struct {
		Logs []LogEntry `json:"logs"`
	}
	json.NewDecoder(rec.Body).Decode(&resp)
	if len(resp.Logs) != 100 {
		t.Errorf("expected default limit 100, got %d", len(resp.Logs))
	}
}

func TestHandleRecentLogsInvalidLimit(t *testing.T) {
	h := newTestHub()
	h.storeRecent(LogEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		Level:     "info",
		Source:    "sprout",
		Message:   "msg",
	})

	handler := handleRecentLogsWithHub(h)
	req := httptest.NewRequest("GET", "/api/v1/logs?limit=abc", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestLogHubBroadcast(t *testing.T) {
	h := newTestHub()

	// Create two clients with different filters
	c1 := &logClient{send: make(chan LogEntry, 10), level: "", source: ""}
	c2 := &logClient{send: make(chan LogEntry, 10), level: "error", source: ""}

	h.register(c1)
	h.register(c2)
	defer h.unregister(c1)
	defer h.unregister(c2)

	h.broadcast(LogEntry{Level: "info", Source: "sprout", Message: "info msg"})

	// c1 should receive (no filter)
	select {
	case msg := <-c1.send:
		if msg.Message != "info msg" {
			t.Errorf("c1 got %q, want %q", msg.Message, "info msg")
		}
	default:
		t.Error("c1 should have received message")
	}

	// c2 should NOT receive (level filter = error)
	select {
	case msg := <-c2.send:
		t.Errorf("c2 should not have received message, got %q", msg.Message)
	default:
		// expected
	}
}
