package router

import (
	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	mcphttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/mcp"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/gofiber/fiber/v2"
)

type mcpRouter struct {
	middlewareTransport *middleware.Transport
	healthHandler       *apihandler.HealthHandler
	mcpHandler          *mcphttp.Handler
}

func NewMCPRouter(
	middlewareTransport *middleware.Transport,
	healthHandler *apihandler.HealthHandler,
	mcpHandler *mcphttp.Handler,
) ServerRouter {
	return &mcpRouter{
		middlewareTransport: middlewareTransport,
		healthHandler:       healthHandler,
		mcpHandler:          mcpHandler,
	}
}

func (r *mcpRouter) BuildRoutes(app *fiber.App) error {
	app.Get(HealthPath, r.healthHandler.Liveness)
	app.Get(ReadyPath, r.healthHandler.Readiness)

	installMiddlewares(app, r.middlewareTransport)
	// Streamable HTTP: JSON-RPC messages are POSTed to the consumer path.
	app.Post("/*", r.mcpHandler.Handle)
	return nil
}
