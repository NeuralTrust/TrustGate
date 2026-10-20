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
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmetricsmocks "github.com/NeuralTrust/TrustGate/pkg/app/metrics/mocks"
	appusagemocks "github.com/NeuralTrust/TrustGate/pkg/app/usage/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

type usageCall struct {
	traceID string
	status  int
	start   time.Time
}

func expectUsage(t *testing.T, enabled bool) (*appusagemocks.RequestRecorder, func() []usageCall) {
	t.Helper()
	rec := appusagemocks.NewRequestRecorder(t)
	rec.EXPECT().Enabled().Return(enabled).Maybe()
	var (
		mu    sync.Mutex
		calls []usageCall
	)
	rec.EXPECT().Record(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, rt *trace.RequestTrace, status int, start time.Time) {
			mu.Lock()
			defer mu.Unlock()
			calls = append(calls, usageCall{traceID: rt.TraceID(), status: status, start: start})
		}).Return().Maybe()
	return rec, func() []usageCall {
		mu.Lock()
		defer mu.Unlock()
		return append([]usageCall(nil), calls...)
	}
}

func usageApp(handler fiber.Handler, mw fiber.Handler, path string) *fiber.App {
	gatewayID := ids.New[ids.GatewayKind]()
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.SetUserContext(appconsumer.WithGatewayID(c.UserContext(), gatewayID))
		return c.Next()
	})
	app.Use(mw)
	app.Post(path, handler)
	return app
}

func TestMetricsMiddleware_RecordsUsageWithTelemetryOff(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)
	rec, calls := expectUsage(t, true)
	mw := middleware.NewMetricsMiddleware(worker, rec, &config.Config{})

	var handlerTrace string
	app := usageApp(func(c *fiber.Ctx) error {
		rt := trace.FromContext(c.UserContext())
		require.NotNil(t, rt, "usage needs the request trace even with telemetry off")
		handlerTrace = rt.TraceID()
		return c.Status(fiber.StatusTooManyRequests).SendString("slow down")
	}, mw.Middleware(), "/v1/chat/completions")

	before := time.Now()
	resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/v1/chat/completions", nil))
	require.NoError(t, err)
	assert.Equal(t, handlerTrace, resp.Header.Get(middleware.HeaderTraceID))

	got := calls()
	require.Len(t, got, 1)
	assert.Equal(t, handlerTrace, got[0].traceID)
	assert.Equal(t, fiber.StatusTooManyRequests, got[0].status)
	assert.False(t, got[0].start.Before(before))
}

func TestMetricsMiddleware_NoTraceWhenTelemetryAndUsageOff(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)
	rec, calls := expectUsage(t, false)
	mw := middleware.NewMetricsMiddleware(worker, rec, &config.Config{})
	app := usageApp(func(c *fiber.Ctx) error {
		assert.Nil(t, trace.FromContext(c.UserContext()))
		return c.SendStatus(fiber.StatusOK)
	}, mw.Middleware(), "/v1/chat/completions")

	_, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/v1/chat/completions", nil))
	require.NoError(t, err)
	assert.Empty(t, calls())
}

func TestMetricsMiddleware_RecordsUsageAndProcessesWithTelemetryOn(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)
	worker.EXPECT().Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Once()
	rec, calls := expectUsage(t, true)
	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	mw := middleware.NewMetricsMiddleware(worker, rec, cfg)
	app := usageApp(func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	}, mw.Middleware(), "/v1/chat/completions")

	_, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/v1/chat/completions", nil))
	require.NoError(t, err)
	got := calls()
	require.Len(t, got, 1)
	assert.Equal(t, fiber.StatusOK, got[0].status)
}

func TestMetricsMiddleware_StreamFinalizerRecordsUsage(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)
	rec, calls := expectUsage(t, true)
	mw := middleware.NewMetricsMiddleware(worker, rec, &config.Config{})
	app := usageApp(func(c *fiber.Ctx) error {
		finalize, ok := c.Locals(infracontext.StreamMetricsFinalizerKey).(infracontext.StreamMetricsFinalizer)
		require.True(t, ok)
		c.Locals(infracontext.StreamMetricsOwnedKey, true)
		finalize(&infracontext.RequestContext{}, []byte("data: done"), fiber.StatusOK, nil)
		return c.SendStatus(fiber.StatusOK)
	}, mw.Middleware(), "/v1/chat/completions")

	_, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/v1/chat/completions", nil))
	require.NoError(t, err)
	got := calls()
	require.Len(t, got, 1)
	assert.Equal(t, fiber.StatusOK, got[0].status)
}

func TestMCPMetricsMiddleware_RecordsUsageWithTelemetryOff(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)
	rec, calls := expectUsage(t, true)
	mw := middleware.NewMCPMetricsMiddleware(worker, rec, &config.Config{})
	app := usageApp(func(c *fiber.Ctx) error {
		require.NotNil(t, trace.FromContext(c.UserContext()))
		return c.Status(fiber.StatusOK).SendString(`{"result":{}}`)
	}, mw.Middleware(), "/mcp")

	_, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/mcp", nil))
	require.NoError(t, err)
	got := calls()
	require.Len(t, got, 1)
	assert.Equal(t, fiber.StatusOK, got[0].status)
}

func TestMCPMetricsMiddleware_SkipOptOutRecordsNoUsage(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)
	rec, calls := expectUsage(t, true)
	mw := middleware.NewMCPMetricsMiddleware(worker, rec, &config.Config{})
	app := usageApp(func(c *fiber.Ctx) error {
		c.Locals(string(infracontext.MCPSkipMetricsKey), true)
		return c.SendStatus(fiber.StatusOK)
	}, mw.Middleware(), "/mcp")

	_, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/mcp", nil))
	require.NoError(t, err)
	assert.Empty(t, calls())
}
