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
	a2ahttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/a2a"
	oauthhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/introspection"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/mtls"
	oidcauth "github.com/NeuralTrust/TrustGate/pkg/infra/auth/oidc"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/NeuralTrust/TrustGate/pkg/server"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"go.uber.org/dig"
)

type agentMiddlewares struct {
	dig.In
	RequestID          *middleware.RequestIDMiddleware
	PanicRecover       *middleware.PanicRecoverMiddleware
	AccessLog          *middleware.AccessLogMiddleware
	SecurityHeaders    *middleware.SecurityHeadersMiddleware
	Auth               *middleware.AgentAuthMiddleware
	HybridGatewayGuard *middleware.HybridGatewayGuardMiddleware
	Metrics            *middleware.AgentMetricsMiddleware
	UsageGuard         *middleware.UsageGuardMiddleware
}

func agentBaseTransport(m agentMiddlewares) *middleware.Transport {
	return middleware.NewTransport(
		m.RequestID,
		m.SecurityHeaders,
		m.PanicRecover,
		m.AccessLog,
	)
}

func agentAuthTransport(m agentMiddlewares) *middleware.Transport {
	return middleware.NewTransport(
		m.Auth,
		m.HybridGatewayGuard,
		m.Metrics,
		m.UsageGuard.ForAgent(),
	)
}

type agentAuthParams struct {
	dig.In
	APIKeys     appauth.APIKeyFinder
	Credentials appauth.CredentialFinder
	Verifier    appauth.JWTVerifier
	Consumers   consumerdomain.Reader
	Auths       authdomain.Repository
	Gateways    gatewaydomain.Repository
	TTLMaps     *cache.TTLMapManager
	DataFinder  appconsumer.DataFinder
	Finder      appgateway.Finder
	Cfg         *config.Config
	Logger      *slog.Logger
}

func provideAgentAuth(p agentAuthParams) *middleware.AgentAuthMiddleware {
	paths := appconsumer.NewAgentPathResolver(p.Consumers, p.Auths, p.Gateways, p.TTLMaps, p.Logger)
	resolver := middleware.NewAgentChainIdentityResolver(
		p.APIKeys,
		p.Credentials,
		paths,
		oidcauth.NewOAuth2TokenValidator(p.Verifier, nil),
		introspection.NewValidator(nil),
		mtls.NewValidator(),
		mtls.NewXFCCExtractor(),
		p.Cfg.Server.TrustXFCCFrom,
	)
	return middleware.NewAgentAuthMiddleware(resolver, p.DataFinder, p.Finder)
}

type agentRouterParams struct {
	dig.In
	BaseTransport *middleware.Transport `name:"agentBase"`
	AuthTransport *middleware.Transport `name:"agentAuth"`
	OpsMetrics    *o11y.Provider
	HealthHandler *apihandler.HealthHandler
	A2AHandler    *a2ahttp.Handler
	JWKSHandler   *oauthhttp.JWKSHandler
}

type agentServerParams struct {
	dig.In
	Cfg    *config.Config
	Logger *slog.Logger
	Router router.ServerRouter `name:"agent"`
}

// ServerAgent provides the A2A agent plane's server.
func ServerAgent(c *container.Container) error {
	if err := c.Provide(provideAgentAuth); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewAgentMetricsMiddleware); err != nil {
		return err
	}
	if err := c.Provide(agentBaseTransport, dig.Name("agentBase")); err != nil {
		return err
	}
	if err := c.Provide(agentAuthTransport, dig.Name("agentAuth")); err != nil {
		return err
	}
	if err := c.Provide(
		func(p agentRouterParams) router.ServerRouter {
			ops := middleware.NewOpsMetricsMiddleware(p.OpsMetrics, o11y.PlaneAgent)
			return router.NewAgentRouter(p.BaseTransport, p.AuthTransport, p.HealthHandler, ops, p.A2AHandler, p.JWKSHandler)
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
