package serve

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/api/client"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/log"
)

// LogEntry matches the JSON structure expected by the web UI's LogEntry type.
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Source    string `json:"source"`
	SourceID  string `json:"sourceId,omitempty"`
	Message   string `json:"message"`
}

// logHub manages WebSocket subscribers for log streaming. It follows
// every cook job the serve user may view over the sealed farmer-to-CLI
// leg (client.FollowJobs, farmer's jobs.follow: sprouts seal their step
// events to the tenant key, which imas serve doesn't hold) and fans out
// log entries to all connected WebSocket clients. Each client can filter
// by level and source.
type logHub struct {
	mu      sync.Mutex
	clients map[*logClient]struct{}

	// recentMu guards the recent log ring buffer.
	recentMu sync.RWMutex
	recent   []LogEntry
}

// logClient represents a single WebSocket subscriber.
type logClient struct {
	conn   *websocket.Conn
	send   chan LogEntry
	level  string // minimum level filter: debug < info < warn < error
	source string // source filter: farmer | sprout | "" (all)
}

const (
	maxRecentLogs = 200
	writeWait     = 10 * time.Second
	pongWait      = 60 * time.Second
	pingPeriod    = 54 * time.Second
	sendBufSize   = 256
)

var (
	hub     *logHub
	hubOnce sync.Once

	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(_ *http.Request) bool {
			return true // local server; all origins allowed
		},
	}

	// levelOrder maps log levels to numeric severity for filtering.
	levelOrder = map[string]int{
		"debug": 0,
		"info":  1,
		"warn":  2,
		"error": 3,
	}
)

// getHub returns the singleton logHub, initializing it on first call.
func getHub() *logHub {
	hubOnce.Do(func() {
		hub = &logHub{
			clients: make(map[*logClient]struct{}),
			recent:  make([]LogEntry, 0, maxRecentLogs),
		}
		hub.subscribeNATS()
	})
	return hub
}

// followLease is how long each follow of every job lasts at farmer, and
// followRenew how often the hub starts the next one: the two overlap, so
// no event falls between them, and the hub drops the duplicates the
// overlap delivers by event ID. followRetry is how soon a follow that
// farmer refused is tried again.
const (
	followLease = 15 * time.Minute
	followRenew = 10 * time.Minute
	followRetry = 30 * time.Second
)

// followRenewAfter and followRetryAfter are the values used; tests shorten
// them.
var (
	followRenewAfter = followRenew
	followRetryAfter = followRetry
)

// followJobs starts a follow of every job and returns its events and the
// function that stops it; a variable so tests can feed the hub without a
// farmer.
var followJobs = func(nc *nats.Conn) (<-chan cook.FollowedStepEvent, func(), error) {
	s, err := client.FollowJobs(nc, "", client.FollowOptions{Max: followLease})
	if err != nil {
		return nil, nil, err
	}
	return s.Events, s.Stop, nil
}

// subscribeNATS starts following every cook job over client.NatsConn.
func (h *logHub) subscribeNATS() {
	if client.NatsConn == nil {
		log.Errorf("logstream: NATS connection not available; log streaming disabled")
		return
	}
	go h.follow(client.NatsConn, nil)
	log.Printf("logstream: following cook step events from farmer (sealed) for log streaming")
}

// follow keeps a follow of every job running until stop closes: it starts
// the next one every followRenew (or followRetry after a refusal) and
// stops the one before once the next is in place.
func (h *logHub) follow(nc *nats.Conn, stop <-chan struct{}) {
	in := make(chan cook.FollowedStepEvent, sendBufSize)
	seen := map[string]time.Time{}
	var stopCur func()
	start := func() time.Duration {
		events, stopNext, err := followJobs(nc)
		if err != nil {
			log.Errorf("logstream: following cook step events: %v", err)
			return followRetryAfter
		}
		go func() {
			for ev := range events {
				select {
				case in <- ev:
				case <-stop:
					return
				}
			}
		}()
		if stopCur != nil {
			stopCur()
		}
		stopCur = stopNext
		return followRenewAfter
	}
	timer := time.NewTimer(start())
	defer timer.Stop()
	defer func() {
		if stopCur != nil {
			stopCur()
		}
	}()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			timer.Reset(start())
			for id, at := range seen {
				if time.Since(at) > 2*followLease {
					delete(seen, id)
				}
			}
		case ev := <-in:
			if _, dup := seen[ev.EventID]; dup {
				continue
			}
			seen[ev.EventID] = time.Now()
			entry := cookEntry(ev)
			h.storeRecent(entry)
			h.broadcast(entry)
		}
	}
}

// cookEntry converts a cook step event into a LogEntry.
func cookEntry(ev cook.FollowedStepEvent) LogEntry {
	step := ev.Step
	level := "debug"
	if step.Error != nil {
		level = "error"
	} else if step.ChangesMade {
		level = "info"
	}
	return LogEntry{
		Timestamp: step.Started.UTC().Format(time.RFC3339),
		Level:     level,
		Source:    "sprout",
		SourceID:  ev.SproutID,
		Message:   formatStepMessage(step, ev.JobID),
	}
}

// formatStepMessage builds a human-readable log message from a StepCompletion.
func formatStepMessage(step cook.StepCompletion, jid string) string {
	status := "completed"
	switch step.CompletionStatus {
	case cook.StepNotStarted:
		status = "not started"
	case cook.StepInProgress:
		status = "in progress"
	case cook.StepFailed:
		status = "failed"
	case cook.StepSkipped:
		status = "skipped"
	case cook.StepCompleted:
		status = "completed"
	}

	msg := "job " + jid + " step " + string(step.ID) + ": " + status
	if step.Error != nil {
		msg += " — " + step.Error.Error()
	}
	if step.ChangesMade && len(step.Changes) > 0 {
		msg += " (changes: "
		for i, c := range step.Changes {
			if i > 0 {
				msg += ", "
			}
			msg += c
			if i >= 4 {
				msg += "..."
				break
			}
		}
		msg += ")"
	}
	if step.Duration > 0 {
		msg += " [" + step.Duration.String() + "]"
	}
	return msg
}

// storeRecent adds an entry to the ring buffer of recent logs.
func (h *logHub) storeRecent(entry LogEntry) {
	h.recentMu.Lock()
	defer h.recentMu.Unlock()

	h.recent = append(h.recent, entry)
	if len(h.recent) > maxRecentLogs {
		// Drop the oldest entries.
		h.recent = h.recent[len(h.recent)-maxRecentLogs:]
	}
}

// getRecent returns a copy of recent log entries, optionally filtered.
func (h *logHub) getRecent(level, source string, limit int) []LogEntry {
	h.recentMu.RLock()
	defer h.recentMu.RUnlock()

	result := make([]LogEntry, 0, len(h.recent))
	for _, entry := range h.recent {
		if !matchesFilter(entry, level, source) {
			continue
		}
		result = append(result, entry)
	}

	if limit > 0 && len(result) > limit {
		result = result[len(result)-limit:]
	}
	return result
}

// broadcast sends a log entry to all connected clients that match filters.
func (h *logHub) broadcast(entry LogEntry) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for c := range h.clients {
		if !matchesFilter(entry, c.level, c.source) {
			continue
		}
		select {
		case c.send <- entry:
		default:
			// Client is too slow; drop the message.
		}
	}
}

// register adds a client to the hub.
func (h *logHub) register(c *logClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[c] = struct{}{}
}

// unregister removes a client from the hub and closes its send channel.
func (h *logHub) unregister(c *logClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.send)
	}
}

// matchesFilter returns true if entry passes the level and source filters.
func matchesFilter(entry LogEntry, level, source string) bool {
	if source != "" && entry.Source != source {
		return false
	}
	if level != "" {
		entryOrd, ok1 := levelOrder[entry.Level]
		filterOrd, ok2 := levelOrder[level]
		if ok1 && ok2 && entryOrd < filterOrd {
			return false
		}
	}
	return true
}

// HandleLogStream upgrades an HTTP request to a WebSocket connection
// and streams log entries to the client.
func HandleLogStream(w http.ResponseWriter, r *http.Request) {
	handleLogStreamWithHub(getHub())(w, r)
}

// handleLogStreamWithHub returns a handler that uses the given hub.
// This is used for testing without the global singleton.
func handleLogStreamWithHub(h *logHub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Errorf("logstream: websocket upgrade failed: %v", err)
			return
		}

		level := r.URL.Query().Get("level")
		source := r.URL.Query().Get("source")

		c := &logClient{
			conn:   conn,
			send:   make(chan LogEntry, sendBufSize),
			level:  level,
			source: source,
		}

		h.register(c)

		go c.writePump()
		go c.readPump(h)
	}
}

// HandleRecentLogs returns recent log entries as JSON. Supports level,
// source, and limit query parameters.
func HandleRecentLogs(w http.ResponseWriter, r *http.Request) {
	handleRecentLogsWithHub(getHub())(w, r)
}

// handleRecentLogsWithHub returns a handler that uses the given hub.
func handleRecentLogsWithHub(h *logHub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		level := r.URL.Query().Get("level")
		source := r.URL.Query().Get("source")
		limit := 100
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				limit = n
			}
		}

		logs := h.getRecent(level, source, limit)
		WriteJSON(w, http.StatusOK, map[string]any{"logs": logs})
	}
}

// writePump writes log entries from the send channel to the WebSocket.
func (c *logClient) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case entry, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, nil)
				return
			}
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump reads from the WebSocket to detect client disconnection.
// It discards all incoming messages.
func (c *logClient) readPump(h *logHub) {
	defer func() {
		h.unregister(c)
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			break
		}
	}
}
