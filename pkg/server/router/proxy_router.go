package router

import (
	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/gofiber/fiber/v2"
)

type proxyRouter struct {
	middlewareTransport *middleware.Transport
	healthHandler       *apihandler.HealthHandler
}

func NewProxyRouter(
	middlewareTransport *middleware.Transport,
	healthHandler *apihandler.HealthHandler,
) ServerRouter {
	return &proxyRouter{
		middlewareTransport: middlewareTransport,
		healthHandler:       healthHandler,
	}
}

func (r *proxyRouter) BuildRoutes(app *fiber.App) error {
	installMiddlewares(app, r.middlewareTransport)
	app.Get(HealthPath, r.healthHandler.Liveness)
	app.Get(ReadyPath, r.healthHandler.Readiness)
	return nil
}
