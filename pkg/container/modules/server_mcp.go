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
	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	oauthhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/server"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"go.uber.org/dig"
)

type mcpMiddlewares struct {
	dig.In
	RequestID       *middleware.RequestIDMiddleware
	PanicRecover    *middleware.PanicRecoverMiddleware
	AccessLog       *middleware.AccessLogMiddleware
	SecurityHeaders *middleware.SecurityHeadersMiddleware
	OAuthChallenge  *middleware.OAuthChallengeMiddleware
	Auth            *middleware.MCPAuthMiddleware
	Metrics         *middleware.MCPMetricsMiddleware
}

func mcpBaseTransport(m mcpMiddlewares) *middleware.Transport {
	return middleware.NewTransport(
		m.RequestID,
		m.SecurityHeaders,
		m.PanicRecover,
		m.AccessLog,
	)
}

func mcpAuthTransport(m mcpMiddlewares) *middleware.Transport {
	return middleware.NewTransport(
		m.OAuthChallenge,
		m.Auth,
		m.Metrics,
	)
}

type mcpRouterParams struct {
	dig.In
	BaseTransport              *middleware.Transport `name:"mcpBase"`
	AuthTransport              *middleware.Transport `name:"mcpAuth"`
	HealthHandler              *apihandler.HealthHandler
	MCPHandler                 *mcphttp.Handler
	ProtectedResourceHandler   *oauthhttp.ProtectedResourceHandler
	AuthorizationServerHandler *oauthhttp.AuthorizationServerHandler
	RegisterHandler            *oauthhttp.RegisterHandler
	AuthorizeHandler           *oauthhttp.AuthorizeHandler
	CallbackHandler            *oauthhttp.CallbackHandler
	TokenHandler               *oauthhttp.TokenHandler
	ConnectHandler             *oauthhttp.ConnectHandler
	JWKSHandler                *oauthhttp.JWKSHandler
}

type mcpServerParams struct {
	dig.In
	Cfg    *config.Config
	Logger *slog.Logger
	Router router.ServerRouter `name:"mcp"`
}

func ServerMCP(c *container.Container) error {
	if err := c.Provide(mcpBaseTransport, dig.Name("mcpBase")); err != nil {
		return err
	}
	if err := c.Provide(mcpAuthTransport, dig.Name("mcpAuth")); err != nil {
		return err
	}
	if err := c.Provide(
		func(p mcpRouterParams) router.ServerRouter {
			return router.NewMCPRouter(
				p.BaseTransport,
				p.AuthTransport,
				p.HealthHandler,
				p.MCPHandler,
				p.ProtectedResourceHandler,
				p.AuthorizationServerHandler,
				p.RegisterHandler,
				p.AuthorizeHandler,
				p.CallbackHandler,
				p.TokenHandler,
				p.ConnectHandler,
				p.JWKSHandler,
			)
		},
		dig.Name("mcp"),
	); err != nil {
		return err
	}
	return c.Provide(
		func(p mcpServerParams) server.Server {
			addr := fmt.Sprintf(":%d", p.Cfg.Server.MCPPort)
			return server.NewHTTPServer("mcp", addr, p.Cfg.Server, p.Logger, []router.ServerRouter{p.Router})
		},
		dig.Name("mcp"),
	)
}
