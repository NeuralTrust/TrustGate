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

// AgentRPCPath is the agent plane's JSON-RPC endpoint.
const AgentRPCPath = "/:consumer/agents/:agent"

type agentRouter struct {
	baseTransport *middleware.Transport
	authTransport *middleware.Transport
	opsMetrics    *middleware.OpsMetricsMiddleware
	healthHandler *apihandler.HealthHandler
}

// NewAgentRouter builds the routes of the A2A agent plane.
func NewAgentRouter(
	baseTransport *middleware.Transport,
	authTransport *middleware.Transport,
	healthHandler *apihandler.HealthHandler,
	opsMetrics *middleware.OpsMetricsMiddleware,
) ServerRouter {
	return &agentRouter{
		baseTransport: baseTransport,
		authTransport: authTransport,
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

	// TODO(a2a): /.well-known/jwks.json goes here, on the base transport, and
	// the agent card route and the A2A handler below, behind the auth transport.
	app.Post(AgentRPCPath, append(r.authTransport.GetMiddlewares(), agentMethodNotFound)...)
	return nil
}

// agentMethodNotFound stands in for the A2A handler until it lands.
func agentMethodNotFound(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"jsonrpc": "2.0",
		"id":      nil,
		"error":   fiber.Map{"code": -32601, "message": "Method not found"},
	})
}
