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
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	clientTraceID     = "4bf92f3577b34da6a3ce929d0e0e4736"
	validTraceparent  = "00-" + clientTraceID + "-00f067aa0ba902b7-01"
	clientMCPSession  = "1868a90c-6c1b-4e1a-9b3f-0c2d2b0c7e11"
	traceparentHeader = "traceparent"
	mcpSessionHeader  = "Mcp-Session-Id"
)

type plane struct {
	name    string
	path    string
	handler func(worker *appmetricsmocks.Worker, cfg *config.Config) fiber.Handler
}

var planes = []plane{
	{
		name: "llm",
		path: "/v1/chat/completions",
		handler: func(w *appmetricsmocks.Worker, cfg *config.Config) fiber.Handler {
			return middleware.NewMetricsMiddleware(w, nil, cfg).Middleware()
		},
	},
	{
		name: "mcp",
		path: "/mcp",
		handler: func(w *appmetricsmocks.Worker, cfg *config.Config) fiber.Handler {
			return middleware.NewMCPMetricsMiddleware(w, nil, cfg).Middleware()
		},
	},
	{
		name: "a2a",
		path: "/bot/agents/research",
		handler: func(w *appmetricsmocks.Worker, cfg *config.Config) fiber.Handler {
			return middleware.NewAgentMetricsMiddleware(w, nil, cfg).Middleware()
		},
	},
}

func tracedMetadata(t *testing.T, p plane, headers map[string][]string) trace.Metadata {
	t.Helper()
	worker := appmetricsmocks.NewWorker(t)
	var (
		mu  sync.Mutex
		got trace.Metadata
	)
	worker.EXPECT().
		Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(rt *trace.RequestTrace, _ *infracontext.RequestContext, _ *infracontext.ResponseContext, _ time.Time, _ time.Time, _ []telemetrydomain.ExporterConfig) {
			mu.Lock()
			defer mu.Unlock()
			got = rt.Metadata()
		}).
		Return().
		Once()

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.SetUserContext(appconsumer.WithGatewayID(c.UserContext(), ids.New[ids.GatewayKind]()))
		return c.Next()
	})
	app.Use(p.handler(worker, cfg))
	app.Post(p.path, func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	req := httptest.NewRequest(fiber.MethodPost, p.path, nil)
	for name, values := range headers {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	resp, err := app.Test(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	mu.Lock()
	defer mu.Unlock()
	return got
}

func TestMetricsMiddlewares_RecordTheClientTraceID(t *testing.T) {
	tests := []struct {
		name        string
		traceparent []string
		want        string
	}{
		{name: "valid", traceparent: []string{validTraceparent}, want: clientTraceID},
		{name: "absent", traceparent: nil, want: ""},
		{name: "invalid", traceparent: []string{"00-" + clientTraceID + "-0000000000000000-01"}, want: ""},
		{name: "repeated", traceparent: []string{validTraceparent, validTraceparent}, want: ""},
	}
	for _, p := range planes {
		for _, tt := range tests {
			t.Run(p.name+"/"+tt.name, func(t *testing.T) {
				meta := tracedMetadata(t, p, map[string][]string{traceparentHeader: tt.traceparent})
				assert.Equal(t, tt.want, meta.ClientTraceID)
			})
		}
	}
}

func TestMetricsMiddlewares_RecordTheMCPSessionOnlyOnMCP(t *testing.T) {
	want := map[string]string{"llm": "", "mcp": clientMCPSession, "a2a": ""}
	for _, p := range planes {
		t.Run(p.name, func(t *testing.T) {
			meta := tracedMetadata(t, p, map[string][]string{mcpSessionHeader: {clientMCPSession}})
			assert.Equal(t, want[p.name], meta.MCPSessionID)
		})
	}
}

func TestMCPMetricsMiddleware_IgnoresAnInvalidMCPSession(t *testing.T) {
	meta := tracedMetadata(t, planes[1], map[string][]string{mcpSessionHeader: {"not a visible-ascii id"}})
	assert.Empty(t, meta.MCPSessionID)
}
