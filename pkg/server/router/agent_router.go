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

package router

import (
	apihandler "github.com/NeuralTrust/TrustGate/pkg/api/handler/http"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/gofiber/fiber/v2"
)

type agentRouter struct {
	baseTransport *middleware.Transport
	opsMetrics    *middleware.OpsMetricsMiddleware
	healthHandler *apihandler.HealthHandler
}

// NewAgentRouter builds the routes of the A2A agent plane.
func NewAgentRouter(
	baseTransport *middleware.Transport,
	healthHandler *apihandler.HealthHandler,
	opsMetrics *middleware.OpsMetricsMiddleware,
) ServerRouter {
	return &agentRouter{
		baseTransport: baseTransport,
		opsMetrics:    opsMetrics,
		healthHandler: healthHandler,
	}
}

func (r *agentRouter) BuildRoutes(app *fiber.App) error {
	if r.opsMetrics != nil {
		app.Use(r.opsMetrics.Middleware())
	}
	app.Get(HealthPath, r.healthHandler.Liveness)
	app.Get(HealthPathAlias, r.healthHandler.Liveness)
	app.Get(ReadyPath, r.healthHandler.Readiness)

	installMiddlewares(app, r.baseTransport)

	// A2A routes go here: /.well-known/jwks.json on the base transport, then
	// the agent card and the JSON-RPC endpoint behind the auth transport.
	return nil
}
