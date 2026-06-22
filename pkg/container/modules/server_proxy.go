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
	proxyhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/proxy"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/server"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"go.uber.org/dig"
)

type proxyMiddlewares struct {
	dig.In
	PanicRecover    *middleware.PanicRecoverMiddleware
	AccessLog       *middleware.AccessLogMiddleware
	SecurityHeaders *middleware.SecurityHeadersMiddleware
	Session         *middleware.SessionMiddleware
	Auth            *middleware.AuthMiddleware
	Metrics         *middleware.MetricsMiddleware
}

func proxyTransport(m proxyMiddlewares) *middleware.Transport {
	return middleware.NewTransport(
		m.SecurityHeaders,
		m.PanicRecover,
		m.AccessLog,
		m.Auth,
		m.Session,
		m.Metrics,
	)
}

type proxyRouterParams struct {
	dig.In
	Transport     *middleware.Transport `name:"proxy"`
	HealthHandler *apihandler.HealthHandler
	ProxyHandler  *proxyhttp.ForwardedHandler
}

type proxyServerParams struct {
	dig.In
	Cfg    *config.Config
	Logger *slog.Logger
	Router router.ServerRouter `name:"proxy"`
}

func ServerProxy(c *container.Container) error {
	if err := c.Provide(proxyTransport, dig.Name("proxy")); err != nil {
		return err
	}
	if err := c.Provide(
		func(p proxyRouterParams) router.ServerRouter {
			return router.NewProxyRouter(p.Transport, p.HealthHandler, p.ProxyHandler)
		},
		dig.Name("proxy"),
	); err != nil {
		return err
	}
	return c.Provide(
		func(p proxyServerParams) server.Server {
			addr := fmt.Sprintf(":%d", p.Cfg.Server.ProxyPort)
			return server.NewHTTPServer("proxy", addr, p.Cfg.Server, p.Logger, []router.ServerRouter{p.Router})
		},
		dig.Name("proxy"),
	)
}
