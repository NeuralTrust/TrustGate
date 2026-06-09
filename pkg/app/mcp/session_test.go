package mcp_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	appmcp "github.com/NeuralTrust/AgentGateway/pkg/app/mcp"
	mcpclient "github.com/NeuralTrust/AgentGateway/pkg/infra/mcp/client"
)

type memoryStore struct {
	mu   sync.Mutex
	pins map[string]appmcp.Pin
}

func newMemoryStore() *memoryStore {
	return &memoryStore{pins: map[string]appmcp.Pin{}}
}

func (s *memoryStore) Get(_ context.Context, key string) (*appmcp.Pin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pin, ok := s.pins[key]; ok {
		return &pin, nil
	}
	return nil, nil
}

func (s *memoryStore) Set(_ context.Context, key string, pin appmcp.Pin) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pins[key] = pin
	return nil
}

func (s *memoryStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pins, key)
	return nil
}

// sessionServer is a minimal stateful MCP upstream: it issues session ids on
// initialize and rejects unknown sessions with 404 (Streamable HTTP spec).
type sessionServer struct {
	mu         sync.Mutex
	inits      int
	valid      map[string]bool
	nextID     int
	callResult string
}

func newSessionServer() *sessionServer {
	return &sessionServer{valid: map[string]bool{}, callResult: `{"content":[{"type":"text","text":"ok"}]}`}
}

func (s *sessionServer) expireAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.valid = map[string]bool{}
}

func (s *sessionServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		sid := r.Header.Get("Mcp-Session-Id")
		if req.Method == "initialize" {
			s.inits++
			s.nextID++
			newSID := "sess-" + string(rune('a'+s.nextID))
			s.valid[newSID] = true
			w.Header().Set("Mcp-Session-Id", newSID)
			writeJSON(w, req.ID, map[string]any{
				"protocolVersion": mcpclient.ProtocolVersion,
				"serverInfo":      map[string]any{"name": "stub", "version": "1"},
			})
			return
		}
		if sid != "" && !s.valid[sid] {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if len(req.ID) == 0 || string(req.ID) == "null" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		switch req.Method {
		case "tools/list":
			writeJSON(w, req.ID, map[string]any{"tools": []map[string]any{{"name": "echo"}}})
		case "tools/call":
			writeJSON(w, req.ID, json.RawMessage(s.callResult))
		default:
			writeJSON(w, req.ID, map[string]any{})
		}
	}
}

func writeJSON(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func TestPinnedDialer_ReusesStoredSession(t *testing.T) {
	upstream := newSessionServer()
	srv := httptest.NewServer(upstream.handler())
	defer srv.Close()

	store := newMemoryStore()
	dialer := appmcp.NewPinnedDialer(mcpclient.New(), store, slog.New(slog.DiscardHandler))
	target := mcpclient.Target{URL: srv.URL, PinKey: "gw:consumer:reg"}

	up, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("first connect: %v", err)
	}
	if _, err := up.ListTools(context.Background()); err != nil {
		t.Fatalf("first list: %v", err)
	}
	if upstream.inits != 1 {
		t.Fatalf("expected 1 initialize, got %d", upstream.inits)
	}
	if pin, _ := store.Get(context.Background(), target.PinKey); pin == nil {
		t.Fatal("expected pin to be stored after connect")
	}

	// Second connect must resume the stored session without re-initializing.
	up2, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("second connect: %v", err)
	}
	if _, err := up2.ListTools(context.Background()); err != nil {
		t.Fatalf("second list: %v", err)
	}
	if upstream.inits != 1 {
		t.Fatalf("expected resumed session (1 initialize), got %d", upstream.inits)
	}
}

func TestPinnedDialer_ReinitializesExpiredSession(t *testing.T) {
	upstream := newSessionServer()
	srv := httptest.NewServer(upstream.handler())
	defer srv.Close()

	store := newMemoryStore()
	dialer := appmcp.NewPinnedDialer(mcpclient.New(), store, slog.New(slog.DiscardHandler))
	target := mcpclient.Target{URL: srv.URL, PinKey: "gw:consumer:reg"}

	up, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := up.CallTool(context.Background(), "echo", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("call: %v", err)
	}

	// Simulate upstream session expiry: the pinned id is now unknown (404).
	upstream.expireAll()

	up2, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if _, err := up2.CallTool(context.Background(), "echo", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("call after expiry should re-init and retry: %v", err)
	}
	if upstream.inits != 2 {
		t.Fatalf("expected re-initialize after expiry (2 inits), got %d", upstream.inits)
	}
	pin, _ := store.Get(context.Background(), target.PinKey)
	if pin == nil {
		t.Fatal("expected refreshed pin after re-init")
	}
}

func TestPinnedDialer_NoPinKeyConnectsDirect(t *testing.T) {
	upstream := newSessionServer()
	srv := httptest.NewServer(upstream.handler())
	defer srv.Close()

	store := newMemoryStore()
	dialer := appmcp.NewPinnedDialer(mcpclient.New(), store, slog.New(slog.DiscardHandler))

	up, err := dialer.Connect(context.Background(), mcpclient.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := up.ListTools(context.Background()); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(store.pins) != 0 {
		t.Fatalf("expected no pins without a pin key, got %d", len(store.pins))
	}
}
