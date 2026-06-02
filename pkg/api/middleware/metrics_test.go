package middleware_test

import (
	"bufio"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appmetricsmocks "github.com/NeuralTrust/AgentGateway/pkg/app/metrics/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domaintelemetry "github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestMetricsMiddleware_ProcessesNonStreamingRequest(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)
	worker.EXPECT().HasDefaultExporters().Return(false)

	var (
		mu      sync.Mutex
		gotReq  *infracontext.RequestContext
		gotResp *infracontext.ResponseContext
		called  bool
	)
	worker.EXPECT().
		Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ []domaintelemetry.ExporterConfig, _ *trace.RequestTrace, req *infracontext.RequestContext, resp *infracontext.ResponseContext, _ time.Time, _ time.Time) {
			mu.Lock()
			defer mu.Unlock()
			called = true
			gotReq = req
			gotResp = resp
		}).
		Return().
		Once()

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true

	mw := middleware.NewMetricsMiddleware(worker, cfg)

	gatewayID := ids.New[ids.GatewayKind]()
	app := fiber.New()
	// Mimic the auth middleware: the gateway id arrives via context, not a header.
	app.Use(func(c *fiber.Ctx) error {
		c.SetUserContext(appconsumer.WithGatewayID(c.UserContext(), gatewayID))
		return c.Next()
	})
	app.Use(mw.Middleware())
	app.Post("/v1/chat/completions", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).SendString("ok")
	})

	req := httptest.NewRequest(fiber.MethodPost, "/v1/chat/completions", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	mu.Lock()
	defer mu.Unlock()
	require.True(t, called, "worker.Process must be called")
	assert.Equal(t, fiber.MethodPost, gotReq.Method)
	assert.Equal(t, "/v1/chat/completions", gotReq.Path)
	assert.Equal(t, gatewayID.String(), gotReq.GatewayID)
	assert.Equal(t, fiber.StatusOK, gotResp.StatusCode)
}

func TestMetricsMiddleware_StreamingEmitsViaFinalizer(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)
	worker.EXPECT().HasDefaultExporters().Return(false)

	var (
		mu       sync.Mutex
		calls    int
		gotReq   *infracontext.RequestContext
		gotResp  *infracontext.ResponseContext
		gotStart time.Time
	)
	worker.EXPECT().
		Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ []domaintelemetry.ExporterConfig, _ *trace.RequestTrace, req *infracontext.RequestContext, resp *infracontext.ResponseContext, start time.Time, _ time.Time) {
			mu.Lock()
			defer mu.Unlock()
			calls++
			gotReq = req
			gotResp = resp
			gotStart = start
		}).
		Return()

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	mw := middleware.NewMetricsMiddleware(worker, cfg)

	// streamReq stands in for the request context the proxy handler retains and
	// passes to the finalizer; its Metadata carries the observed usage.
	streamReq := &infracontext.RequestContext{
		GatewayID: "gw-1",
		BackendID: "bk-1",
		Metadata: map[string]interface{}{
			"usage": "recorded",
		},
	}

	app := fiber.New()
	app.Use(mw.Middleware())
	app.Post("/v1/chat/completions", func(c *fiber.Ctx) error {
		finalizer, ok := c.Locals(infracontext.StreamMetricsFinalizerKey).(infracontext.StreamMetricsFinalizer)
		require.True(t, ok, "middleware must stash a stream finalizer")
		c.Locals(infracontext.StreamMetricsOwnedKey, true)
		c.Response().Header.SetContentType("text/event-stream")
		c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
			defer finalizer(streamReq, []byte("data: hi\n"), fiber.StatusOK, map[string][]string{"Content-Type": {"text/event-stream"}})
			_, _ = w.WriteString("data: hi\n")
			_ = w.Flush()
		})
		return nil
	})

	req := httptest.NewRequest(fiber.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Gateway-Id", "gw-1")
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, "data: hi\n", string(body))

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, calls, "streaming must emit exactly once (finalizer), not via the on-the-way-out defer")
	require.NotNil(t, gotResp)
	assert.True(t, gotResp.Streaming, "finalizer marks the response as streamed")
	assert.Equal(t, "data: hi\n", string(gotResp.Body), "captured stream output reaches metrics")
	assert.Same(t, streamReq, gotReq, "finalizer uses the handler request context (carries usage)")
	assert.False(t, gotStart.IsZero(), "start time captured at request entry")
}

func TestMetricsMiddleware_DisabledSkipsWorker(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)
	worker.EXPECT().HasDefaultExporters().Return(false)

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = false

	mw := middleware.NewMetricsMiddleware(worker, cfg)

	app := fiber.New()
	app.Use(mw.Middleware())
	app.Get("/v1/x", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/v1/x", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	worker.AssertNotCalled(t, "Process", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
