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
	a2ahttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/a2a"
	oauthhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/gofiber/fiber/v2"
)

// Agent plane routes.
const (
	AgentRPCPath  = "/:consumer/agents/:agent"
	AgentCardPath = AgentRPCPath + "/.well-known/agent-card.json"
)

type agentRouter struct {
	baseTransport *middleware.Transport
	authTransport *middleware.Transport
	opsMetrics    *middleware.OpsMetricsMiddleware
	healthHandler *apihandler.HealthHandler
	a2aHandler    *a2ahttp.Handler
	jwksHandler   *oauthhttp.JWKSHandler
}

// NewAgentRouter builds the routes of the A2A agent plane.
func NewAgentRouter(
	baseTransport *middleware.Transport,
	authTransport *middleware.Transport,
	healthHandler *apihandler.HealthHandler,
	opsMetrics *middleware.OpsMetricsMiddleware,
	a2aHandler *a2ahttp.Handler,
	jwksHandler *oauthhttp.JWKSHandler,
) ServerRouter {
	return &agentRouter{
		baseTransport: baseTransport,
		authTransport: authTransport,
		opsMetrics:    opsMetrics,
		healthHandler: healthHandler,
		a2aHandler:    a2aHandler,
		jwksHandler:   jwksHandler,
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

	app.Get(oauthhttp.JWKSPath, r.jwksHandler.Handle)

	app.Get(AgentCardPath, append(r.authTransport.GetMiddlewares(), r.a2aHandler.Card)...)
	app.Post(AgentRPCPath, append(r.authTransport.GetMiddlewares(), r.a2aHandler.RPC)...)
	return nil
}
