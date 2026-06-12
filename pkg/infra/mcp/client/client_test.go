package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	appmcp "github.com/NeuralTrust/AgentGateway/pkg/app/mcp"
	mcpclient "github.com/NeuralTrust/AgentGateway/pkg/infra/mcp/client"
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

	raw, err := sess.CallTool(context.Background(), "echo", json.RawMessage(`{"message":"hi"}`))
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

	_, err := sess.CallTool(context.Background(), "missing", nil)
	if err == nil {
		t.Fatal("expected an error for an unknown tool")
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

func TestPing(t *testing.T) {
	t.Parallel()
	srv := newUpstream(t, nil, nil)
	sess := connect(t, appmcp.Target{URL: srv.URL})
	if err := sess.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}
