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
	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	proxyhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/proxy"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/gofiber/fiber/v2"
)

type proxyRouter struct {
	middlewareTransport *middleware.Transport
	healthHandler       *apihandler.HealthHandler
	proxyHandler        *proxyhttp.ForwardedHandler
}

func NewProxyRouter(
	middlewareTransport *middleware.Transport,
	healthHandler *apihandler.HealthHandler,
	proxyHandler *proxyhttp.ForwardedHandler,
) ServerRouter {
	return &proxyRouter{
		middlewareTransport: middlewareTransport,
		healthHandler:       healthHandler,
		proxyHandler:        proxyHandler,
	}
}

func (r *proxyRouter) BuildRoutes(app *fiber.App) error {
	app.Get(HealthPath, r.healthHandler.Liveness)
	app.Get(ReadyPath, r.healthHandler.Readiness)

	installMiddlewares(app, r.middlewareTransport)
	app.All("/*", r.proxyHandler.Handle)
	return nil
}
