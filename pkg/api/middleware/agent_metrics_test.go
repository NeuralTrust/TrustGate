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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAgentMetricsMiddleware_TracesAsA2A(t *testing.T) {
	worker := appmetricsmocks.NewWorker(t)
	var (
		mu    sync.Mutex
		gotRT *trace.RequestTrace
	)
	worker.EXPECT().
		Process(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(rt *trace.RequestTrace, _ *infracontext.RequestContext, _ *infracontext.ResponseContext, _ time.Time, _ time.Time, _ []telemetrydomain.ExporterConfig) {
			mu.Lock()
			defer mu.Unlock()
			gotRT = rt
		}).
		Return().
		Once()

	cfg := &config.Config{}
	cfg.Telemetry.Enabled = true
	mw := middleware.NewAgentMetricsMiddleware(worker, nil, cfg)

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.SetUserContext(appconsumer.WithGatewayID(c.UserContext(), ids.New[ids.GatewayKind]()))
		return c.Next()
	})
	app.Use(mw.Middleware())
	app.Post("/bot/agents/research", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, "/bot/agents/research", nil))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.NotEmpty(t, resp.Header.Get(middleware.HeaderTraceID))

	mu.Lock()
	defer mu.Unlock()
	require.NotNil(t, gotRT)
	require.Equal(t, "a2a", gotRT.Metadata().Kind)
	require.Equal(t, gotRT.TraceID(), resp.Header.Get(middleware.HeaderTraceID))
}
