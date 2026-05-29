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
	proxyHandler        *proxyhttp.ProxyHandler
}

func NewProxyRouter(
	middlewareTransport *middleware.Transport,
	healthHandler *apihandler.HealthHandler,
	proxyHandler *proxyhttp.ProxyHandler,
) ServerRouter {
	return &proxyRouter{
		middlewareTransport: middlewareTransport,
		healthHandler:       healthHandler,
		proxyHandler:        proxyHandler,
	}
}

func (r *proxyRouter) BuildRoutes(app *fiber.App) error {
	installMiddlewares(app, r.middlewareTransport)
	app.Get(HealthPath, r.healthHandler.Liveness)
	app.Get(ReadyPath, r.healthHandler.Readiness)
	app.All("/v1/*", r.proxyHandler.Handle)
	return nil
}
