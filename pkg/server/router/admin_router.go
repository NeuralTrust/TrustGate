package router

import (
	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/gofiber/fiber/v2"
)

const (
	HealthPath  = "/healthz"
	ReadyPath   = "/readyz"
	VersionPath = "/__/version"
)

type adminRouter struct {
	middlewareTransport *middleware.Transport
	healthHandler       *apihandler.HealthHandler
	versionHandler      *apihandler.VersionHandler
}

func NewAdminRouter(
	middlewareTransport *middleware.Transport,
	healthHandler *apihandler.HealthHandler,
	versionHandler *apihandler.VersionHandler,
) ServerRouter {
	return &adminRouter{
		middlewareTransport: middlewareTransport,
		healthHandler:       healthHandler,
		versionHandler:      versionHandler,
	}
}

func (r *adminRouter) BuildRoutes(app *fiber.App) error {
	installMiddlewares(app, r.middlewareTransport)
	app.Get(HealthPath, r.healthHandler.Liveness)
	app.Get(ReadyPath, r.healthHandler.Readiness)
	app.Get(VersionPath, r.versionHandler.Handle)
	return nil
}

func installMiddlewares(app *fiber.App, transport *middleware.Transport) {
	for _, h := range transport.GetMiddlewares() {
		app.Use(h)
	}
}
