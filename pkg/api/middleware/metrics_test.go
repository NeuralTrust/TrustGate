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
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	appmetricsmocks "github.com/NeuralTrust/AgentGateway/pkg/app/metrics/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	telemetrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestMetricsMiddleware_ProcessesNonStreamingRequest(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)

	var (
		mu      sync.Mutex
		gotReq  *infracontext.RequestContext
		gotResp *infracontext.ResponseContext
		called  bool
	)
	worker.EXPECT().
		Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ *trace.RequestTrace, req *infracontext.RequestContext, resp *infracontext.ResponseContext, _ time.Time, _ time.Time, _ []telemetrydomain.ExporterConfig) {
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

func TestMetricsMiddleware_TraceIDMatchesTraceIDHeader(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)

	var (
		mu           sync.Mutex
		gotTraceID   string
		processCalls int
	)
	worker.EXPECT().
		Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(rt *trace.RequestTrace, _ *infracontext.RequestContext, _ *infracontext.ResponseContext, _ time.Time, _ time.Time, _ []telemetrydomain.ExporterConfig) {
			mu.Lock()
			defer mu.Unlock()
			processCalls++
			gotTraceID = rt.TraceID()
		}).
		Return().
		Once()

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	mw := middleware.NewMetricsMiddleware(worker, cfg)

	gatewayID := ids.New[ids.GatewayKind]()
	app := fiber.New()
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

	respTraceID := resp.Header.Get(middleware.HeaderTraceID)
	require.NotEmpty(t, respTraceID, "metrics middleware must echo X-AG-Trace-Id")
	assert.Empty(t, resp.Header.Get(fiber.HeaderXRequestID), "proxy must not set X-Request-Id")

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 1, processCalls)
	assert.Equal(t, respTraceID, gotTraceID, "event TraceID must equal the X-AG-Trace-Id returned to the client")
}

func TestMetricsMiddleware_StreamingEmitsViaFinalizer(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)

	var (
		mu       sync.Mutex
		calls    int
		gotReq   *infracontext.RequestContext
		gotResp  *infracontext.ResponseContext
		gotStart time.Time
	)
	worker.EXPECT().
		Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ *trace.RequestTrace, req *infracontext.RequestContext, resp *infracontext.ResponseContext, start time.Time, _ time.Time, _ []telemetrydomain.ExporterConfig) {
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
		GatewayID:  "gw-1",
		RegistryID: "bk-1",
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

func TestMetricsMiddleware_PassesGatewayExporters(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)

	var (
		mu           sync.Mutex
		gotExporters []telemetrydomain.ExporterConfig
	)
	worker.EXPECT().
		Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ *trace.RequestTrace, _ *infracontext.RequestContext, _ *infracontext.ResponseContext, _ time.Time, _ time.Time, exporters []telemetrydomain.ExporterConfig) {
			mu.Lock()
			defer mu.Unlock()
			gotExporters = exporters
		}).
		Return().
		Once()

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	mw := middleware.NewMetricsMiddleware(worker, cfg)

	gatewayID := ids.New[ids.GatewayKind]()
	gw := &gatewaydomain.Gateway{
		ID: gatewayID,
		Telemetry: &telemetrydomain.Telemetry{
			Exporters: []telemetrydomain.ExporterConfig{
				{Name: "kafka", Settings: map[string]interface{}{"topic": "extra"}},
			},
		},
	}

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithGatewayID(c.UserContext(), gatewayID)
		ctx = appgateway.WithGateway(ctx, gw)
		c.SetUserContext(ctx)
		return c.Next()
	})
	app.Use(mw.Middleware())
	app.Post("/v1/chat/completions", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/v1/chat/completions", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, gotExporters, 1)
	assert.Equal(t, "kafka", gotExporters[0].Name)
	assert.Equal(t, "extra", gotExporters[0].Settings["topic"])
}
