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

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmetricsmocks "github.com/NeuralTrust/TrustGate/pkg/app/metrics/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestMCPMetricsMiddleware_PublishesDispatchedRequest(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)

	var (
		mu     sync.Mutex
		called bool
		gotRT  *trace.RequestTrace
	)
	worker.EXPECT().
		Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(rt *trace.RequestTrace, _ *infracontext.RequestContext, _ *infracontext.ResponseContext, _ time.Time, _ time.Time, _ []telemetrydomain.ExporterConfig) {
			mu.Lock()
			defer mu.Unlock()
			called = true
			gotRT = rt
		}).
		Return().
		Once()

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	mw := middleware.NewMCPMetricsMiddleware(worker, cfg)

	gatewayID := ids.New[ids.GatewayKind]()
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.SetUserContext(appconsumer.WithGatewayID(c.UserContext(), gatewayID))
		return c.Next()
	})
	app.Use(mw.Middleware())
	app.Post("/mcp", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).SendString(`{"result":{}}`)
	})

	resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/mcp", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	mu.Lock()
	defer mu.Unlock()
	require.True(t, called, "worker.Process must be called for dispatched MCP requests")
	require.NotNil(t, gotRT)
	assert.Equal(t, events.KindMCP, gotRT.Metadata().Kind)
}

func TestMCPMetricsMiddleware_SkipsWhenHandlerOptsOut(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	mw := middleware.NewMCPMetricsMiddleware(worker, cfg)

	gatewayID := ids.New[ids.GatewayKind]()
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.SetUserContext(appconsumer.WithGatewayID(c.UserContext(), gatewayID))
		return c.Next()
	})
	app.Use(mw.Middleware())
	app.Post("/mcp", func(c *fiber.Ctx) error {
		c.Locals(string(infracontext.MCPSkipMetricsKey), true)
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/mcp", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	worker.AssertNotCalled(t, "Process", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// The middleware used to call Response().Body() unconditionally, which on a
// body-stream response drains the whole lease into a buffer and delivers it as
// one burst at close. A claimed stream must be emitted once, by the finalizer,
// with no body at all.
func TestMCPMetricsMiddleware_ClaimedStreamEmitsOnceWithoutDrainingTheBody(t *testing.T) {
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
		Run(func(
			_ *trace.RequestTrace,
			req *infracontext.RequestContext,
			resp *infracontext.ResponseContext,
			start time.Time,
			_ time.Time,
			_ []telemetrydomain.ExporterConfig,
		) {
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
	mw := middleware.NewMCPMetricsMiddleware(worker, cfg)

	callsAtOpen := -1
	app := fiber.New()
	app.Use(mw.Middleware())
	app.Post("/mcp", func(c *fiber.Ctx) error {
		finalizer, ok := c.Locals(infracontext.StreamMetricsFinalizerKey).(infracontext.StreamMetricsFinalizer)
		require.True(t, ok, "middleware must stash a stream finalizer")
		c.Locals(infracontext.StreamMetricsOwnedKey, true)
		c.Response().Header.SetContentType("text/event-stream")
		c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
			mu.Lock()
			callsAtOpen = calls
			mu.Unlock()
			defer finalizer(nil, nil, fiber.StatusOK, map[string][]string{"Content-Type": {"text/event-stream"}})
			_, _ = w.WriteString("event: message\ndata: {}\n\n")
			_ = w.Flush()
		})
		return nil
	})

	resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/mcp", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, "event: message\ndata: {}\n\n", string(body), "the client still receives every frame")

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, 0, callsAtOpen, "the handler unwind must not emit a claimed stream")
	require.Equal(t, 1, calls, "a claimed stream is emitted exactly once")
	require.NotNil(t, gotReq, "a nil finalizer request falls back to the captured one")
	require.NotNil(t, gotResp)
	assert.True(t, gotResp.Streaming)
	assert.Nil(t, gotResp.Body, "a live stream must never be buffered into the event")
	assert.False(t, gotStart.IsZero())
}

// Even a stream nobody claimed must not be drained: the guard reports it as
// streaming with no body rather than collapsing chunked delivery.
func TestMCPMetricsMiddleware_UnclaimedStreamIsNotDrained(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)

	var (
		mu      sync.Mutex
		gotResp *infracontext.ResponseContext
	)
	worker.EXPECT().
		Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(
			_ *trace.RequestTrace,
			_ *infracontext.RequestContext,
			resp *infracontext.ResponseContext,
			_ time.Time,
			_ time.Time,
			_ []telemetrydomain.ExporterConfig,
		) {
			mu.Lock()
			defer mu.Unlock()
			gotResp = resp
		}).
		Return().
		Once()

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	mw := middleware.NewMCPMetricsMiddleware(worker, cfg)

	app := fiber.New()
	app.Use(mw.Middleware())
	app.Post("/mcp", func(c *fiber.Ctx) error {
		c.Response().Header.SetContentType("text/event-stream")
		c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
			_, _ = w.WriteString("event: message\ndata: {}\n\n")
			_ = w.Flush()
		})
		return nil
	})

	resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/mcp", nil))
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, "event: message\ndata: {}\n\n", string(body))

	mu.Lock()
	defer mu.Unlock()
	require.NotNil(t, gotResp)
	assert.True(t, gotResp.Streaming)
	assert.Nil(t, gotResp.Body)
}

// A buffered response is the overwhelming majority of MCP traffic and must keep
// reporting its body exactly as before.
func TestMCPMetricsMiddleware_BufferedResponseStillCarriesItsBody(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)

	var (
		mu      sync.Mutex
		gotResp *infracontext.ResponseContext
	)
	worker.EXPECT().
		Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(
			_ *trace.RequestTrace,
			_ *infracontext.RequestContext,
			resp *infracontext.ResponseContext,
			_ time.Time,
			_ time.Time,
			_ []telemetrydomain.ExporterConfig,
		) {
			mu.Lock()
			defer mu.Unlock()
			gotResp = resp
		}).
		Return().
		Once()

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	mw := middleware.NewMCPMetricsMiddleware(worker, cfg)

	app := fiber.New()
	app.Use(mw.Middleware())
	app.Post("/mcp", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).SendString(`{"result":{}}`)
	})

	resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/mcp", nil))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	mu.Lock()
	defer mu.Unlock()
	require.NotNil(t, gotResp)
	assert.False(t, gotResp.Streaming)
	assert.Equal(t, `{"result":{}}`, string(gotResp.Body))
}

func TestMCPMetricsMiddleware_DisabledSkipsWorker(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = false
	mw := middleware.NewMCPMetricsMiddleware(worker, cfg)

	app := fiber.New()
	app.Use(mw.Middleware())
	app.Post("/mcp", func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/mcp", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	worker.AssertNotCalled(t, "Process", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
