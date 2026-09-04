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
	diagnosticshttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/diagnostics"
	proxyhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/proxy"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/gofiber/fiber/v2"
)

// DiagnosticsTestConnectionPath runs the registry connection probe from this
// data plane's own network, authorized by a control-plane diagnostics token.
const DiagnosticsTestConnectionPath = "/__diagnostics/gateways/:gateway_id/registries/test-connection"

type proxyRouter struct {
	middlewareTransport *middleware.Transport
	opsMetrics          *middleware.OpsMetricsMiddleware
	healthHandler       *apihandler.HealthHandler
	proxyHandler        *proxyhttp.ForwardedHandler
	diagnostics         *diagnosticshttp.TestConnectionHandler
}

func NewProxyRouter(
	middlewareTransport *middleware.Transport,
	healthHandler *apihandler.HealthHandler,
	proxyHandler *proxyhttp.ForwardedHandler,
	opsMetrics *middleware.OpsMetricsMiddleware,
	diagnostics *diagnosticshttp.TestConnectionHandler,
) ServerRouter {
	return &proxyRouter{
		middlewareTransport: middlewareTransport,
		opsMetrics:          opsMetrics,
		healthHandler:       healthHandler,
		proxyHandler:        proxyHandler,
		diagnostics:         diagnostics,
	}
}

func (r *proxyRouter) BuildRoutes(app *fiber.App) error {
	// OPS metrics wrap probes and traffic; auth stays after readiness routes.
	if r.opsMetrics != nil {
		app.Use(r.opsMetrics.Middleware())
	}
	app.Get(HealthPath, r.healthHandler.Liveness)
	app.Get(HealthPathAlias, r.healthHandler.Liveness)
	app.Get(ReadyPath, r.healthHandler.Readiness)
	// Registered before the transport like the probes: the handler carries its
	// own token auth, and the consumer auth chain would reject it otherwise.
	app.Post(DiagnosticsTestConnectionPath, r.diagnostics.Handle)

	installMiddlewares(app, r.middlewareTransport)
	app.All("/*", r.proxyHandler.Handle)
	return nil
}
