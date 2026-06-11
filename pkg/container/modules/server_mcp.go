package modules

import (
	"fmt"
	"log/slog"

	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	mcphttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/mcp"
	oauthhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/oauth"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/server"
	"github.com/NeuralTrust/AgentGateway/pkg/server/router"
	"go.uber.org/dig"
)

type mcpMiddlewares struct {
	dig.In
	RequestID       *middleware.RequestIDMiddleware
	PanicRecover    *middleware.PanicRecoverMiddleware
	AccessLog       *middleware.AccessLogMiddleware
	SecurityHeaders *middleware.SecurityHeadersMiddleware
	OAuthChallenge  *middleware.OAuthChallengeMiddleware
	Auth            *middleware.AuthMiddleware
}

// mcpBaseTransport carries the observability middlewares installed before any
// route, so the public OAuth surface (discovery, token, callbacks) is logged
// too.
func mcpBaseTransport(m mcpMiddlewares) *middleware.Transport {
	return middleware.NewTransport(
		m.RequestID,
		m.SecurityHeaders,
		m.PanicRecover,
		m.AccessLog,
	)
}

// mcpAuthTransport guards only the consumer JSON-RPC surface.
func mcpAuthTransport(m mcpMiddlewares) *middleware.Transport {
	return middleware.NewTransport(
		// Challenge must wrap Auth so 401s carry WWW-Authenticate.
		m.OAuthChallenge,
		m.Auth,
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
