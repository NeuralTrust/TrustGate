package modules

import (
	"fmt"
	"log/slog"

	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	mcphttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/mcp"
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
	Auth            *middleware.AuthMiddleware
}

func mcpTransport(m mcpMiddlewares) *middleware.Transport {
	return middleware.NewTransport(
		m.RequestID,
		m.SecurityHeaders,
		m.PanicRecover,
		m.AccessLog,
		m.Auth,
	)
}

type mcpRouterParams struct {
	dig.In
	Transport     *middleware.Transport `name:"mcp"`
	HealthHandler *apihandler.HealthHandler
	MCPHandler    *mcphttp.Handler
}

type mcpServerParams struct {
	dig.In
	Cfg    *config.Config
	Logger *slog.Logger
	Router router.ServerRouter `name:"mcp"`
}

func ServerMCP(c *container.Container) error {
	if err := c.Provide(mcpTransport, dig.Name("mcp")); err != nil {
		return err
	}
	if err := c.Provide(
		func(p mcpRouterParams) router.ServerRouter {
			return router.NewMCPRouter(p.Transport, p.HealthHandler, p.MCPHandler)
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
