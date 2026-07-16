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
	"encoding/json"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	mcpmocks "github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	appmetricsmocks "github.com/NeuralTrust/TrustGate/pkg/app/metrics/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type stubPricing struct{}

func (stubPricing) Resolve(context.Context, string, string) appcatalog.Pricing {
	return appcatalog.Pricing{}
}

func TestMCPPipeline_ToolsCallBuildsMCPEvent(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)

	var (
		mu       sync.Mutex
		gotRT    *trace.RequestTrace
		gotReq   *infracontext.RequestContext
		gotResp  *infracontext.ResponseContext
		gotStart time.Time
		gotEnd   time.Time
	)
	worker.EXPECT().
		Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(rt *trace.RequestTrace, req *infracontext.RequestContext, resp *infracontext.ResponseContext, start, end time.Time, _ []telemetrydomain.ExporterConfig) {
			mu.Lock()
			defer mu.Unlock()
			gotRT, gotReq, gotResp, gotStart, gotEnd = rt, req, resp, start, end
		}).
		Return().
		Once()

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	mw := middleware.NewMCPMetricsMiddleware(worker, cfg)

	composer := mcpmocks.NewComposer(t)
	composer.EXPECT().
		CallTool(mock.Anything, mock.Anything, "echo", mock.Anything).
		Return(json.RawMessage(`{"content":[]}`), nil).
		Once()
	gateway := mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(nil, nil), nil)

	gatewayID := ids.New[ids.GatewayKind]()
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.SetUserContext(appconsumer.WithGatewayID(c.UserContext(), gatewayID))
		return c.Next()
	})
	app.Use(mw.Middleware())
	app.Post("/mcp", func(c *fiber.Ctx) error {
		if rt := trace.FromContext(c.UserContext()); rt != nil {
			rt.SetConsumer("consumer-1", "agent")
		}
		_, err := gateway.Dispatch(c.UserContext(), &appconsumer.RoutableConsumer{}, "tools/call", json.RawMessage(`{"name":"echo"}`))
		require.NoError(t, err)
		return c.Status(fiber.StatusOK).SendString(`{"result":{}}`)
	})

	resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/mcp", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	mu.Lock()
	defer mu.Unlock()
	require.NotNil(t, gotRT, "worker.Process must receive the request trace")

	builder := appmetrics.NewBuilder(adapter.NewRegistry(), stubPricing{})
	evt := builder.Build(context.Background(), gotRT, gotReq, gotResp, gotStart, gotEnd)

	assert.Equal(t, events.KindMCP, evt.Kind)
	require.NotNil(t, evt.MCP)
	assert.Equal(t, "tools/call", evt.MCP.Method)
	assert.Equal(t, "tool", evt.MCP.Operation)
	assert.Equal(t, "echo", evt.MCP.Tool)
	assert.Equal(t, "ok", evt.MCP.UpstreamStatus)
	assert.Equal(t, "consumer-1", evt.Consumer.ID)
}
