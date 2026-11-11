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

package modules

import (
	"fmt"
	"log/slog"

	apihandler "github.com/NeuralTrust/TrustGate/pkg/api/handler/http"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/NeuralTrust/TrustGate/pkg/server"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"go.uber.org/dig"
)

type agentMiddlewares struct {
	dig.In
	RequestID       *middleware.RequestIDMiddleware
	PanicRecover    *middleware.PanicRecoverMiddleware
	AccessLog       *middleware.AccessLogMiddleware
	SecurityHeaders *middleware.SecurityHeadersMiddleware
}

func agentBaseTransport(m agentMiddlewares) *middleware.Transport {
	return middleware.NewTransport(
		m.RequestID,
		m.SecurityHeaders,
		m.PanicRecover,
		m.AccessLog,
	)
}

type agentRouterParams struct {
	dig.In
	BaseTransport *middleware.Transport `name:"agentBase"`
	OpsMetrics    *o11y.Provider
	HealthHandler *apihandler.HealthHandler
}

type agentServerParams struct {
	dig.In
	Cfg    *config.Config
	Logger *slog.Logger
	Router router.ServerRouter `name:"agent"`
}

// ServerAgent provides the A2A agent plane's server.
func ServerAgent(c *container.Container) error {
	if err := c.Provide(agentBaseTransport, dig.Name("agentBase")); err != nil {
		return err
	}
	if err := c.Provide(
		func(p agentRouterParams) router.ServerRouter {
			ops := middleware.NewOpsMetricsMiddleware(p.OpsMetrics, o11y.PlaneAgent)
			return router.NewAgentRouter(p.BaseTransport, p.HealthHandler, ops)
		},
		dig.Name("agent"),
	); err != nil {
		return err
	}
	return c.Provide(
		func(p agentServerParams) server.Server {
			addr := fmt.Sprintf(":%d", p.Cfg.Server.AgentPort)
			return server.NewHTTPServer("agent", addr, p.Cfg.Server, p.Logger, []router.ServerRouter{p.Router})
		},
		dig.Name("agent"),
	)
}
