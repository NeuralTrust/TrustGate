package client_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	appmcp "github.com/NeuralTrust/AgentGateway/pkg/app/mcp"
	mcpclient "github.com/NeuralTrust/AgentGateway/pkg/infra/mcp/client"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// upstreamStub is a real SDK MCP server that counts initialize calls and can
// be swapped out to simulate upstream session loss.
type upstreamStub struct {
	srv     *httptest.Server
	handler atomic.Pointer[http.Handler]
	inits   atomic.Int64
}

func newUpstreamStub(t *testing.T) *upstreamStub {
	t.Helper()
	u := &upstreamStub{}
	u.reset()
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*u.handler.Load()).ServeHTTP(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

// reset swaps in a fresh MCP server: previously issued session ids become
// unknown, which is exactly what an upstream restart or session reap does.
func (u *upstreamStub) reset() {
	server := sdk.NewServer(&sdk.Implementation{Name: "stub", Version: "1"}, nil)
	server.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "initialize" {
				u.inits.Add(1)
			}
			return next(ctx, method, req)
		}
	})
	server.AddTool(
		&sdk.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)},
		func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "ok"}}}, nil
		},
	)
	var handler http.Handler = sdk.NewStreamableHTTPHandler(
		func(*http.Request) *sdk.Server { return server }, nil)
	u.handler.Store(&handler)
}

func newCachedDialer() appmcp.Dialer {
	return mcpclient.NewCachedDialer(mcpclient.New(), slog.New(slog.DiscardHandler))
}

func TestCachedDialer_ReusesSessionPerPinKey(t *testing.T) {
	t.Parallel()
	upstream := newUpstreamStub(t)
	dialer := newCachedDialer()
	target := appmcp.Target{URL: upstream.srv.URL, PinKey: "gw:consumer:reg"}

	for i := 0; i < 3; i++ {
		up, err := dialer.Connect(context.Background(), target)
		if err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
		if _, err := up.ListTools(context.Background()); err != nil {
			t.Fatalf("list %d: %v", i, err)
		}
		up.Close(context.Background())
	}
	if got := upstream.inits.Load(); got != 1 {
		t.Fatalf("expected 1 initialize for a pinned target, got %d", got)
	}
}

func TestCachedDialer_RecoversFromLostUpstreamSession(t *testing.T) {
	t.Parallel()
	upstream := newUpstreamStub(t)
	dialer := newCachedDialer()
	target := appmcp.Target{URL: upstream.srv.URL, PinKey: "gw:consumer:reg"}

	up, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := up.CallTool(context.Background(), "echo", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("call: %v", err)
	}

	// Simulate upstream restart: the cached session id is now unknown.
	upstream.reset()

	up2, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if _, err := up2.CallTool(context.Background(), "echo", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("call after upstream restart should re-initialize and retry: %v", err)
	}
	// One initialize for the first session plus exactly one re-initialize
	// after the restart.
	if got := upstream.inits.Load(); got != 2 {
		t.Fatalf("expected 2 initializes in total (initial + recovery), got %d", got)
	}
}

func TestCachedDialer_NoPinKeyConnectsFresh(t *testing.T) {
	t.Parallel()
	upstream := newUpstreamStub(t)
	dialer := newCachedDialer()
	target := appmcp.Target{URL: upstream.srv.URL}

	for i := 0; i < 2; i++ {
		up, err := dialer.Connect(context.Background(), target)
		if err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
		if _, err := up.ListTools(context.Background()); err != nil {
			t.Fatalf("list %d: %v", i, err)
		}
		up.Close(context.Background())
	}
	if got := upstream.inits.Load(); got != 2 {
		t.Fatalf("expected a fresh session per connect without a pin key, got %d inits", got)
	}
}

func TestCachedDialer_CredentialChangeGetsNewSession(t *testing.T) {
	t.Parallel()
	upstream := newUpstreamStub(t)
	dialer := newCachedDialer()

	for _, token := range []string{"Bearer a", "Bearer b"} {
		up, err := dialer.Connect(context.Background(), appmcp.Target{
			URL:     upstream.srv.URL,
			PinKey:  "gw:consumer:reg:user",
			Headers: map[string]string{"Authorization": token},
		})
		if err != nil {
			t.Fatalf("connect with %q: %v", token, err)
		}
		if _, err := up.ListTools(context.Background()); err != nil {
			t.Fatalf("list with %q: %v", token, err)
		}
	}
	if got := upstream.inits.Load(); got != 2 {
		t.Fatalf("expected distinct sessions per credential fingerprint, got %d inits", got)
	}
}
