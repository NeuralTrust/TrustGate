package proxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	proxyhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/proxy"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appproxy "github.com/NeuralTrust/AgentGateway/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/AgentGateway/pkg/app/proxy/mocks"
	domainconsumer "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

const proxyPath = "/v1/chat/completions"

// authStub mimics the auth middleware: it attaches a resolved gateway id and a
// consumer.Data read model (with one consumer bound to proxyPath) to the request
// context, exactly as the real auth middleware will once credential validation
// lands.
func authStub(gatewayID uuid.UUID, path string) fiber.Handler {
	data := appconsumer.NewData(gatewayID, []appconsumer.RoutableConsumer{
		{Consumer: &domainconsumer.Consumer{ID: uuid.New(), GatewayID: gatewayID, Path: path, Active: true}},
	})
	return func(c *fiber.Ctx) error {
		ctx := appconsumer.WithGatewayID(c.UserContext(), gatewayID)
		ctx = appconsumer.WithData(ctx, data)
		c.SetUserContext(ctx)
		return c.Next()
	}
}

func newTestApp(t *testing.T) (*fiber.App, *proxymocks.Forwarder) {
	t.Helper()
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	app.Use(authStub(uuid.New(), proxyPath))
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/v1/*", handler.Handle)
	return app, fwd
}

// newUnauthenticatedApp wires the handler with no auth context, simulating an
// unidentified request.
func newUnauthenticatedApp(t *testing.T) (*fiber.App, *proxymocks.Forwarder) {
	t.Helper()
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/v1/*", handler.Handle)
	return app, fwd
}

func newProxyRequest() *http.Request {
	req := httptest.NewRequest(http.MethodPost, proxyPath, strings.NewReader(`{"model":"gpt"}`))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func decodeError(t *testing.T, body io.Reader) helpers.ErrorBody {
	t.Helper()
	var eb helpers.ErrorBody
	if err := json.NewDecoder(body).Decode(&eb); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	return eb
}

func TestHandle_Unauthenticated(t *testing.T) {
	app, _ := newUnauthenticatedApp(t)

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if eb := decodeError(t, resp.Body); eb.Error != "unauthenticated" {
		t.Fatalf("error = %q, want unauthenticated", eb.Error)
	}
}

func TestHandle_PathNotFound(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	app.Use(authStub(uuid.New(), "/v1/some/other/path"))
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/v1/*", handler.Handle)

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if eb := decodeError(t, resp.Body); eb.Error != "not_found" {
		t.Fatalf("error = %q, want not_found", eb.Error)
	}
}

func TestHandle_Success_RelaysResponse(t *testing.T) {
	app, fwd := newTestApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.MatchedBy(func(in appproxy.ForwardInput) bool {
			return in.Request != nil && in.Request.Method == http.MethodPost && in.Consumer != nil
		})).
		Return(&appproxy.ForwardResult{
			StatusCode: 200,
			Headers: map[string][]string{
				"Content-Type":        {"application/json"},
				"X-Selected-Provider": {"openai"},
				"Transfer-Encoding":   {"chunked"},
			},
			Body: []byte(`{"ok":true}`),
		}, nil).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Selected-Provider"); got != "openai" {
		t.Fatalf("X-Selected-Provider = %q, want openai", got)
	}
	if got := resp.Header.Get("Transfer-Encoding"); got == "chunked" {
		t.Fatal("hop-by-hop Transfer-Encoding header should not be relayed")
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"ok":true}` {
		t.Fatalf("body = %q", string(body))
	}
}

func TestHandle_Streaming_RelaysSSE(t *testing.T) {
	app, fwd := newTestApp(t)
	lines := [][]byte{
		[]byte("data: {\"delta\":\"hi\"}"),
		{},
		[]byte("data: [DONE]"),
	}
	stream := func(yield func([]byte, error) bool) {
		for _, l := range lines {
			if !yield(l, nil) {
				return
			}
		}
	}
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(&appproxy.ForwardResult{
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"text/event-stream"}, "X-Selected-Provider": {"openai"}},
			Stream:     stream,
		}, nil).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", got)
	}
	if got := resp.Header.Get("X-Selected-Provider"); got != "openai" {
		t.Fatalf("X-Selected-Provider = %q, want openai", got)
	}
	body, _ := io.ReadAll(resp.Body)
	want := "data: {\"delta\":\"hi\"}\n\ndata: [DONE]\n"
	if string(body) != want {
		t.Fatalf("body = %q, want %q", string(body), want)
	}
}

func TestHandle_Streaming_InvokesFinalizerWithCapturedOutput(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	stream := func(yield func([]byte, error) bool) {
		for _, l := range [][]byte{[]byte("data: a"), []byte("data: b")} {
			if !yield(l, nil) {
				return
			}
		}
	}
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(&appproxy.ForwardResult{
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"text/event-stream"}},
			Stream:     stream,
		}, nil).
		Once()

	var (
		mu         sync.Mutex
		calls      int
		gotOutput  []byte
		gotStatus  int
		gotReqBody []byte
		owned      bool
	)
	app := fiber.New()
	app.Use(authStub(uuid.New(), proxyPath))
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(infracontext.StreamMetricsFinalizerKey, infracontext.StreamMetricsFinalizer(
			func(req *infracontext.RequestContext, output []byte, statusCode int, _ map[string][]string) {
				mu.Lock()
				defer mu.Unlock()
				calls++
				gotOutput = output
				gotStatus = statusCode
				gotReqBody = req.Body
			}))
		err := c.Next()
		mu.Lock()
		owned, _ = c.Locals(infracontext.StreamMetricsOwnedKey).(bool)
		mu.Unlock()
		return err
	})
	handler := proxyhttp.NewForwardedHandler(fwd)
	app.All("/v1/*", handler.Handle)

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	_, _ = io.ReadAll(resp.Body)

	mu.Lock()
	defer mu.Unlock()
	if !owned {
		t.Fatal("stream writer must claim metrics ownership")
	}
	if calls != 1 {
		t.Fatalf("finalizer calls = %d, want 1", calls)
	}
	if gotStatus != 200 {
		t.Fatalf("finalizer status = %d, want 200", gotStatus)
	}
	if string(gotOutput) != "data: a\ndata: b\n" {
		t.Fatalf("captured output = %q", string(gotOutput))
	}
	if string(gotReqBody) != `{"model":"gpt"}` {
		t.Fatalf("finalizer req body = %q, want detached request body", string(gotReqBody))
	}
}

func TestHandle_InvalidRequestPayload(t *testing.T) {
	app, fwd := newTestApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(nil, appproxy.ErrInvalidRequestPayload).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if eb := decodeError(t, resp.Body); eb.Error != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", eb.Error)
	}
}

func TestHandle_NoBackendAvailable(t *testing.T) {
	app, fwd := newTestApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(nil, appproxy.ErrNoBackendsInPool).
		Once()

	resp, err := app.Test(newProxyRequest())
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}
