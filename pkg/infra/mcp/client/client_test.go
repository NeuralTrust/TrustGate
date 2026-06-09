package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubServer struct {
	t            *testing.T
	useSSE       bool
	sessionID    string
	gotInit      bool
	gotInitNotif bool
	tools        []Tool
	callResult   string
	rpcErr       *RPCError
	sawHeaders   http.Header
}

func (s *stubServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.sawHeaders = r.Header.Clone()
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		var req jsonrpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.t.Fatalf("decode request: %v", err)
		}
		if req.ID == nil {
			if req.Method == "notifications/initialized" {
				s.gotInitNotif = true
			}
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var result any
		switch req.Method {
		case "initialize":
			s.gotInit = true
			if s.sessionID != "" {
				w.Header().Set(headerSessionID, s.sessionID)
			}
			result = initializeResult{
				ProtocolVersion: ProtocolVersion,
				ServerInfo:      implementation{Name: "stub", Version: "1"},
			}
		case "tools/list":
			result = listToolsResult{Tools: s.tools}
		case "tools/call":
			result = json.RawMessage(s.callResult)
		case "ping":
			result = struct{}{}
		default:
			s.t.Fatalf("unexpected method %s", req.Method)
		}
		res := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if s.rpcErr != nil && req.Method == "tools/call" {
			res["error"] = s.rpcErr
		} else {
			res["result"] = result
		}
		payload, err := json.Marshal(res)
		if err != nil {
			s.t.Fatalf("marshal response: %v", err)
		}
		if s.useSSE {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
	}
}

func TestClient_ConnectListCall_JSON(t *testing.T) {
	t.Parallel()
	stub := &stubServer{
		t:          t,
		sessionID:  "sess-123",
		tools:      []Tool{{Name: "create_issue"}, {Name: "list_repos"}},
		callResult: `{"content":[{"type":"text","text":"ok"}]}`,
	}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	c := New()
	s, err := c.Connect(context.Background(), Target{URL: srv.URL, Headers: map[string]string{"X-Custom": "v"}})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !stub.gotInit || !stub.gotInitNotif {
		t.Fatalf("handshake incomplete: init=%v notif=%v", stub.gotInit, stub.gotInitNotif)
	}
	if stub.sawHeaders.Get("X-Custom") != "v" {
		t.Fatal("custom header not forwarded")
	}

	tools, err := s.ListTools(context.Background())
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools) != 2 || tools[0].Name != "create_issue" {
		t.Fatalf("tools = %+v", tools)
	}
	if stub.sawHeaders.Get(headerSessionID) != "sess-123" {
		t.Fatal("session id not replayed after initialize")
	}

	res, err := s.CallTool(context.Background(), "create_issue", json.RawMessage(`{"title":"x"}`))
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if string(res) != stub.callResult {
		t.Fatalf("result = %s", res)
	}
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestClient_SSEResponse(t *testing.T) {
	t.Parallel()
	stub := &stubServer{t: t, useSSE: true, tools: []Tool{{Name: "search"}}}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	c := New()
	s, err := c.Connect(context.Background(), Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	tools, err := s.ListTools(context.Background())
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "search" {
		t.Fatalf("tools = %+v", tools)
	}
}

func TestClient_UpstreamRPCErrorPassthrough(t *testing.T) {
	t.Parallel()
	stub := &stubServer{
		t:      t,
		tools:  []Tool{{Name: "x"}},
		rpcErr: &RPCError{Code: -32602, Message: "unknown tool"},
	}
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()

	c := New()
	s, err := c.Connect(context.Background(), Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	_, err = s.CallTool(context.Background(), "x", nil)
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != -32602 {
		t.Fatalf("error = %v, want RPCError -32602", err)
	}
}

func TestClient_UnreachableUpstream(t *testing.T) {
	t.Parallel()
	c := New()
	_, err := c.Connect(context.Background(), Target{URL: "http://127.0.0.1:1"})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("error = %v, want ErrUnreachable", err)
	}
}

func TestClient_ServerErrorIsUnreachable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c := New()
	_, err := c.Connect(context.Background(), Target{URL: srv.URL})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("error = %v, want ErrUnreachable", err)
	}
}
