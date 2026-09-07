// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	mcpclient "github.com/NeuralTrust/TrustGate/pkg/infra/mcp/client"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func newUpstream(t *testing.T, configure func(*sdk.Server), wrap func(http.Handler) http.Handler) *httptest.Server {
	t.Helper()
	server := sdk.NewServer(&sdk.Implementation{Name: "stub", Version: "1"}, nil)
	if configure != nil {
		configure(server)
	}
	var handler http.Handler = sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return server }, nil)
	if wrap != nil {
		handler = wrap(handler)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

func addEchoTool(server *sdk.Server) {
	server.AddTool(
		&sdk.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(_ context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			var args struct {
				Message string `json:"message"`
			}
			_ = json.Unmarshal(req.Params.Arguments, &args)
			return &sdk.CallToolResult{
				Content: []sdk.Content{&sdk.TextContent{Text: "echo:" + args.Message}},
			}, nil
		},
	)
}

func connect(t *testing.T, target appmcp.Target) *mcpclient.Session {
	t.Helper()
	sess, err := mcpclient.New().Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { sess.Close(context.Background()) })
	return sess
}

func TestConnect_UnreachableUpstream(t *testing.T) {
	t.Parallel()
	_, err := mcpclient.New().Connect(context.Background(), appmcp.Target{URL: "http://127.0.0.1:1/mcp"})
	if !errors.Is(err, appmcp.ErrUnreachable) {
		t.Fatalf("error = %v, want ErrUnreachable", err)
	}
}

func TestConnect_UnreachableErrorDoesNotExposeURLQuery(t *testing.T) {
	t.Parallel()

	const secret = "query-secret-sentinel"
	_, err := mcpclient.New().Connect(
		context.Background(),
		appmcp.Target{URL: "http://127.0.0.1:1/private?token=" + secret},
	)
	if !errors.Is(err, appmcp.ErrUnreachable) {
		t.Fatalf("error = %v, want ErrUnreachable", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error exposed URL query: %v", err)
	}
}

func TestConnect_RejectsInvalidEndpointAndHeadersBeforeNetwork(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	t.Cleanup(srv.Close)

	tests := []struct {
		name   string
		target appmcp.Target
	}{
		{
			name:   "userinfo",
			target: appmcp.Target{URL: strings.Replace(srv.URL, "http://", "http://user:password@", 1)},
		},
		{
			name:   "fragment",
			target: appmcp.Target{URL: srv.URL + "/mcp#secret"},
		},
		{
			name:   "empty explicit port",
			target: appmcp.Target{URL: "http://127.0.0.1:/mcp"},
		},
		{
			name: "reserved header",
			target: appmcp.Target{
				URL:     srv.URL,
				Headers: map[string]string{"Content-Type": "text/plain"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mcpclient.New().Connect(context.Background(), tt.target)
			if !errors.Is(err, appmcp.ErrUnreachable) {
				t.Fatalf("error = %v, want ErrUnreachable", err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream contacted %d times", calls.Load())
	}
}

func TestConnectLegacy_PreservesSDKSessionStateAndLifecycle(t *testing.T) {
	t.Parallel()

	type wireRequest struct {
		httpMethod      string
		rpcMethod       string
		protocolVersion string
	}
	var mu sync.Mutex
	var requests []wireRequest
	srv := newUpstream(t, func(server *sdk.Server) {
		addEchoTool(server)
	}, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var rpcMethod string
			if r.Method == http.MethodPost {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read request body: %v", err)
					return
				}
				if err := r.Body.Close(); err != nil {
					t.Errorf("close request body: %v", err)
					return
				}
				r.Body = io.NopCloser(strings.NewReader(string(body)))
				var envelope struct {
					Method string `json:"method"`
				}
				if err := json.Unmarshal(body, &envelope); err != nil {
					t.Errorf("decode request body: %v", err)
					return
				}
				rpcMethod = envelope.Method
			}
			mu.Lock()
			requests = append(requests, wireRequest{
				httpMethod:      r.Method,
				rpcMethod:       rpcMethod,
				protocolVersion: r.Header.Get("Mcp-Protocol-Version"),
			})
			mu.Unlock()
			next.ServeHTTP(w, r)
		})
	})

	sess, err := mcpclient.New().ConnectLegacy(context.Background(), appmcp.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := sess.ListTools(context.Background()); err != nil {
		t.Fatalf("list tools: %v", err)
	}
	sess.Close(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 4 {
		t.Fatalf("wire requests = %+v, want initialize, initialized, tools/list and DELETE", requests)
	}
	if requests[0].rpcMethod != "initialize" {
		t.Fatalf("first remote method = %q, want initialize", requests[0].rpcMethod)
	}
	for _, request := range requests {
		if request.rpcMethod == "server/discover" {
			t.Fatalf("wire requests = %+v, server/discover must stay local", requests)
		}
	}
	if requests[1].rpcMethod != "notifications/initialized" ||
		requests[1].protocolVersion != "2025-11-25" {
		t.Fatalf("initialized request = %+v, want legacy protocol header", requests[1])
	}
	if requests[2].rpcMethod != "tools/list" ||
		requests[2].protocolVersion != "2025-11-25" {
		t.Fatalf("tools/list request = %+v, want legacy protocol header", requests[2])
	}
	if requests[3].httpMethod != http.MethodDelete ||
		requests[3].protocolVersion != "2025-11-25" {
		t.Fatalf("close request = %+v, want one versioned DELETE", requests[3])
	}
}

// newLegacyUpstream serves a pre-2026 upstream that rejects server/discover and
// only completes the handshake for the given protocol revision, recording every
// revision it was offered. An empty accepted revision rejects all of them.
func newLegacyUpstream(
	t *testing.T,
	accepted string,
	offered *offeredVersions,
	discoverRequests *atomic.Int64,
) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		method, id := readRequestEnvelope(t, req)
		switch method {
		case "server/discover":
			discoverRequests.Add(1)
			w.WriteHeader(http.StatusBadRequest)
		case "initialize":
			version := readInitializeVersion(t, req)
			offered.add(version)
			if accepted == "" || version != accepted {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "legacy-session")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(id) +
				`,"result":{"protocolVersion":"` + accepted +
				`","capabilities":{"tools":{}},"serverInfo":{"name":"legacy","version":"1"}}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			http.Error(w, "unexpected method", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestConnect_RetriesLegacyAfterInitializeBadRequest(t *testing.T) {
	t.Parallel()
	var discoverRequests atomic.Int64
	var offered offeredVersions
	srv := newLegacyUpstream(t, "2025-06-18", &offered, &discoverRequests)

	sess, err := mcpclient.New().Connect(context.Background(), appmcp.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { sess.Close(context.Background()) })

	if got := discoverRequests.Load(); got != 0 {
		t.Fatalf("server/discover requests = %d, want 0; the legacy era never dials a modern method", got)
	}
	want := []string{"2025-11-25", "2025-06-18"}
	if got := offered.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("offered protocol versions = %v, want %v", got, want)
	}
}

func TestConnect_WalksLegacyProtocolVersionsUntilAccepted(t *testing.T) {
	t.Parallel()
	var discoverRequests atomic.Int64
	var offered offeredVersions
	srv := newLegacyUpstream(t, "2024-11-05", &offered, &discoverRequests)

	sess, err := mcpclient.New().Connect(context.Background(), appmcp.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { sess.Close(context.Background()) })

	want := []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}
	if got := offered.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("offered protocol versions = %v, want %v", got, want)
	}
}

func TestConnect_ExhaustsLegacyProtocolVersions(t *testing.T) {
	t.Parallel()
	var discoverRequests atomic.Int64
	var offered offeredVersions
	srv := newLegacyUpstream(t, "", &offered, &discoverRequests)

	_, err := mcpclient.New().Connect(context.Background(), appmcp.Target{URL: srv.URL})
	if !errors.Is(err, appmcp.ErrUnreachable) {
		t.Fatalf("error = %v, want ErrUnreachable", err)
	}
	if !strings.Contains(err.Error(), "2024-11-05") {
		t.Fatalf("error = %v, want it to name the last protocol version offered", err)
	}
	want := []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}
	if got := offered.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("offered protocol versions = %v, want %v", got, want)
	}
}

func TestConnect_DoesNotRetryAuthFailures(t *testing.T) {
	t.Parallel()
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			var requests atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests.Add(1)
				w.WriteHeader(status)
			}))
			t.Cleanup(srv.Close)

			_, err := mcpclient.New().Connect(context.Background(), appmcp.Target{URL: srv.URL})
			if !errors.Is(err, appmcp.ErrUnreachable) {
				t.Fatalf("error = %v, want ErrUnreachable", err)
			}
			if status == http.StatusUnauthorized && !errors.Is(err, appmcp.ErrUpstreamUnauthorized) {
				t.Fatalf("error = %v, want ErrUpstreamUnauthorized", err)
			}
			if got := requests.Load(); got != 1 {
				t.Fatalf("requests = %d, want 1: initialize only, with discover answered locally", got)
			}
		})
	}
}

func TestConnect_DoesNotRetryAfterContextCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	var discoverRequests atomic.Int64
	var initializeRequests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch readRequestMethod(t, req) {
		case "server/discover":
			discoverRequests.Add(1)
			w.WriteHeader(http.StatusBadRequest)
		case "initialize":
			initializeRequests.Add(1)
			cancel()
			w.WriteHeader(http.StatusBadRequest)
		default:
			http.Error(w, "unexpected method", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	_, err := mcpclient.New().Connect(ctx, appmcp.Target{URL: srv.URL})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if got := discoverRequests.Load(); got != 0 {
		t.Fatalf("server/discover requests = %d, want 0", got)
	}
	if got := initializeRequests.Load(); got != 1 {
		t.Fatalf("initialize requests = %d, want 1 without a legacy retry", got)
	}
}

// Which era an upstream speaks is decided by the negotiating dialer's probe
// before Connect is ever called (see probe_test.go and negotiating_dialer_test.go);
// Connect is the legacy adapter and answers server/discover locally, so the two
// tests that used to pin era selection here — a modern discover error must not
// downgrade, and a modern upstream must be served through discover alone — now
// belong to those suites.

func TestConnect_DoesNotForwardCredentialsAcrossRedirects(t *testing.T) {
	t.Parallel()
	var redirectedRequests atomic.Int64
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		redirectedRequests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(redirectTarget.Close)

	redirectSource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, redirectTarget.URL, http.StatusFound)
	}))
	t.Cleanup(redirectSource.Close)

	_, err := mcpclient.New().Connect(context.Background(), appmcp.Target{
		URL:     redirectSource.URL,
		Headers: map[string]string{"Authorization": "Bearer secret"},
	})
	if !errors.Is(err, appmcp.ErrUnreachable) {
		t.Fatalf("error = %v, want ErrUnreachable", err)
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Fatalf("redirect target requests = %d, want 0", got)
	}
}

func TestSession_ExposesUpstreamUnauthorized(t *testing.T) {
	t.Parallel()
	srv := newUpstream(t, addEchoTool, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if readRequestMethod(t, req) == "tools/list" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, req)
		})
	})
	sess := connect(t, appmcp.Target{URL: srv.URL})

	_, err := sess.ListTools(context.Background())
	if !errors.Is(err, appmcp.ErrUpstreamUnauthorized) {
		t.Fatalf("error = %v, want ErrUpstreamUnauthorized", err)
	}
}

type offeredVersions struct {
	mu       sync.Mutex
	versions []string
}

func (o *offeredVersions) add(version string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.versions = append(o.versions, version)
}

func (o *offeredVersions) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.versions)
}

func readInitializeVersion(t *testing.T, req *http.Request) string {
	t.Helper()
	if req.Body == nil {
		return ""
	}
	data, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	var envelope struct {
		Params struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"params"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	return envelope.Params.ProtocolVersion
}

func readRequestMethod(t *testing.T, req *http.Request) string {
	t.Helper()
	method, _ := readRequestEnvelope(t, req)
	return method
}

func readRequestEnvelope(t *testing.T, req *http.Request) (string, json.RawMessage) {
	t.Helper()
	if req.Body == nil {
		return "", nil
	}
	data, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	if len(data) == 0 {
		return "", nil
	}
	var envelope struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	return envelope.Method, envelope.ID
}

func TestListTools_AndCallTool(t *testing.T) {
	t.Parallel()
	srv := newUpstream(t, addEchoTool, nil)
	sess := connect(t, appmcp.Target{URL: srv.URL})

	tools, err := sess.ListTools(context.Background())
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "echo" {
		t.Fatalf("tools = %+v, want [echo]", tools)
	}

	raw, err := sess.CallTool(context.Background(), appmcp.ToolCall{
		Name:      "echo",
		Arguments: json.RawMessage(`{"message":"hi"}`),
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if !strings.Contains(string(raw), "echo:hi") {
		t.Fatalf("result = %s, want it to contain echo:hi", raw)
	}
}

func TestCallTool_UnknownToolIsRPCError(t *testing.T) {
	t.Parallel()
	srv := newUpstream(t, addEchoTool, nil)
	sess := connect(t, appmcp.Target{URL: srv.URL})

	_, err := sess.CallTool(context.Background(), appmcp.ToolCall{Name: "missing"})
	if err == nil {
		t.Fatal("expected an error for an unknown tool")
		return
	}
	if !appmcp.IsRPCError(err) {
		t.Fatalf("error = %v, want a JSON-RPC error", err)
	}
}

func TestHeadersInjectedOnEveryRequest(t *testing.T) {
	t.Parallel()
	var missed atomic.Int64
	srv := newUpstream(t, addEchoTool, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer secret" {
				missed.Add(1)
			}
			next.ServeHTTP(w, r)
		})
	})
	sess := connect(t, appmcp.Target{
		URL:     srv.URL,
		Headers: map[string]string{"Authorization": "Bearer secret"},
	})
	if _, err := sess.ListTools(context.Background()); err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if missed.Load() != 0 {
		t.Fatalf("%d requests arrived without the configured header", missed.Load())
	}
}

func TestHeadersRemainIsolatedAcrossLegacyConnections(t *testing.T) {
	t.Parallel()

	var missed atomic.Int64
	newAuthorizedUpstream := func(token string) *httptest.Server {
		return newUpstream(t, addEchoTool, func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != token || r.Header.Get("X-Target") != token {
					missed.Add(1)
				}
				next.ServeHTTP(w, r)
			})
		})
	}

	targets := []appmcp.Target{
		{
			URL:     newAuthorizedUpstream("Bearer alpha").URL,
			Headers: map[string]string{"Authorization": "Bearer alpha", "X-Target": "Bearer alpha"},
		},
		{
			URL:     newAuthorizedUpstream("Bearer beta").URL,
			Headers: map[string]string{"Authorization": "Bearer beta", "X-Target": "Bearer beta"},
		},
	}

	var wg sync.WaitGroup
	for _, target := range targets {
		target := target
		wg.Go(func() {
			sess := connect(t, target)
			if _, err := sess.ListTools(context.Background()); err != nil {
				t.Errorf("list tools: %v", err)
			}
		})
	}
	wg.Wait()
	if missed.Load() != 0 {
		t.Fatalf("%d requests used headers from another target", missed.Load())
	}
}

func TestResources_ListAndRead(t *testing.T) {
	t.Parallel()
	srv := newUpstream(t, func(server *sdk.Server) {
		server.AddResource(
			&sdk.Resource{URI: "file:///readme", Name: "readme", MIMEType: "text/plain"},
			func(context.Context, *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
				return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{
					{URI: "file:///readme", MIMEType: "text/plain", Text: "hello"},
				}}, nil
			},
		)
	}, nil)
	sess := connect(t, appmcp.Target{URL: srv.URL})

	if !sess.SupportsResources() {
		t.Fatal("expected the upstream to advertise resources")
	}
	resources, err := sess.ListResources(context.Background())
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	if len(resources) != 1 || resources[0].URI != "file:///readme" {
		t.Fatalf("resources = %+v, want [file:///readme]", resources)
	}

	raw, err := sess.ReadResource(context.Background(), "file:///readme")
	if err != nil {
		t.Fatalf("read resource: %v", err)
	}
	if !strings.Contains(string(raw), `"hello"`) {
		t.Fatalf("result = %s, want it to contain hello", raw)
	}
}

func TestPrompts_ListAndGet(t *testing.T) {
	t.Parallel()
	srv := newUpstream(t, func(server *sdk.Server) {
		server.AddPrompt(
			&sdk.Prompt{Name: "greet", Description: "say hi"},
			func(_ context.Context, req *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
				return &sdk.GetPromptResult{Messages: []*sdk.PromptMessage{
					{Role: "user", Content: &sdk.TextContent{Text: "hi " + req.Params.Arguments["name"]}},
				}}, nil
			},
		)
	}, nil)
	sess := connect(t, appmcp.Target{URL: srv.URL})

	if !sess.SupportsPrompts() {
		t.Fatal("expected the upstream to advertise prompts")
	}
	prompts, err := sess.ListPrompts(context.Background())
	if err != nil {
		t.Fatalf("list prompts: %v", err)
	}
	if len(prompts) != 1 || prompts[0].Name != "greet" {
		t.Fatalf("prompts = %+v, want [greet]", prompts)
	}

	raw, err := sess.GetPrompt(context.Background(), "greet", map[string]string{"name": "ana"})
	if err != nil {
		t.Fatalf("get prompt: %v", err)
	}
	if !strings.Contains(string(raw), "hi ana") {
		t.Fatalf("result = %s, want it to contain hi ana", raw)
	}
}

func TestCapabilityGating_ToolsOnlyUpstream(t *testing.T) {
	t.Parallel()
	srv := newUpstream(t, addEchoTool, nil)
	sess := connect(t, appmcp.Target{URL: srv.URL})

	resources, err := sess.ListResources(context.Background())
	if err != nil || len(resources) != 0 {
		t.Fatalf("resources = %v, %v; want empty without error", resources, err)
	}
	prompts, err := sess.ListPrompts(context.Background())
	if err != nil || len(prompts) != 0 {
		t.Fatalf("prompts = %v, %v; want empty without error", prompts, err)
	}
	if _, err := sess.ReadResource(context.Background(), "file:///x"); !errors.Is(err, appmcp.ErrNotSupported) {
		t.Fatalf("read error = %v, want ErrNotSupported", err)
	}
	if _, err := sess.GetPrompt(context.Background(), "x", nil); !errors.Is(err, appmcp.ErrNotSupported) {
		t.Fatalf("get prompt error = %v, want ErrNotSupported", err)
	}
}

func TestSessionErrorsDoNotExposeURLQuery(t *testing.T) {
	t.Parallel()

	const secret = "session-query-secret-sentinel"
	srv := newUpstream(t, addEchoTool, nil)
	sess := connect(t, appmcp.Target{URL: srv.URL + "?token=" + secret})
	_, err := sess.ReadResource(context.Background(), "file:///x")
	if !errors.Is(err, appmcp.ErrNotSupported) {
		t.Fatalf("error = %v, want ErrNotSupported", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("session error exposed URL query: %v", err)
	}
}

func TestPing(t *testing.T) {
	t.Parallel()
	srv := newUpstream(t, nil, nil)
	sess := connect(t, appmcp.Target{URL: srv.URL})
	if err := sess.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestSessionCloseWaitsForActiveCall(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	release := make(chan struct{})
	server := sdk.NewServer(&sdk.Implementation{Name: "stub", Version: "1"}, nil)
	server.AddTool(
		&sdk.Tool{Name: "blocked", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			close(started)
			<-release
			return &sdk.CallToolResult{}, nil
		},
	)
	srv := httptest.NewServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, nil))
	t.Cleanup(srv.Close)
	sess, err := mcpclient.New().Connect(context.Background(), appmcp.Target{URL: srv.URL})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	callDone := make(chan error, 1)
	go func() {
		_, err := sess.CallTool(context.Background(), appmcp.ToolCall{Name: "blocked"})
		callDone <- err
	}()
	<-started
	closeDone := make(chan struct{})
	go func() {
		sess.Close(context.Background())
		close(closeDone)
	}()
	select {
	case <-closeDone:
		t.Fatal("session closed while a call was active")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-callDone; err != nil {
		t.Fatalf("call: %v", err)
	}
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("session close did not finish")
	}
	if err := sess.Ping(context.Background()); err == nil {
		t.Fatal("closed session accepted a new operation")
	}
}
