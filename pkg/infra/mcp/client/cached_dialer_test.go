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

	upstream.reset()

	up2, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if _, err := up2.CallTool(context.Background(), "echo", json.RawMessage(`{}`)); err == nil {
		t.Fatal("call on a lost session must propagate the error instead of retrying")
	}

	up3, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("reconnect after eviction: %v", err)
	}
	if _, err := up3.CallTool(context.Background(), "echo", json.RawMessage(`{}`)); err != nil {
		t.Fatalf("call after re-dial: %v", err)
	}
	if got := upstream.inits.Load(); got != 2 {
		t.Fatalf("expected 2 initializes in total (initial + recovery), got %d", got)
	}
}

func TestCachedDialer_ListRetriesAfterLostSession(t *testing.T) {
	t.Parallel()
	upstream := newUpstreamStub(t)
	dialer := newCachedDialer()
	target := appmcp.Target{URL: upstream.srv.URL, PinKey: "gw:consumer:reg"}

	up, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if _, err := up.ListTools(context.Background()); err != nil {
		t.Fatalf("list: %v", err)
	}

	upstream.reset()

	up2, err := dialer.Connect(context.Background(), target)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if _, err := up2.ListTools(context.Background()); err != nil {
		t.Fatalf("read-only list should transparently re-initialize and retry: %v", err)
	}
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
