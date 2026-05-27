package modules

import (
	"fmt"
	"log/slog"

	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/server"
	"github.com/NeuralTrust/AgentGateway/pkg/server/router"
	"go.uber.org/dig"
)

type adminMiddlewares struct {
	dig.In
	RequestID       *middleware.RequestIDMiddleware
	PanicRecover    *middleware.PanicRecoverMiddleware
	AccessLog       *middleware.AccessLogMiddleware
	CORS            *middleware.CORSMiddleware
	SecurityHeaders *middleware.SecurityHeadersMiddleware
}

func adminTransport(m adminMiddlewares) *middleware.Transport {
	return middleware.NewTransport(
		m.RequestID,
		m.SecurityHeaders,
		m.CORS,
		m.PanicRecover,
		m.AccessLog,
	)
}

type adminRouterParams struct {
	dig.In
	Transport      *middleware.Transport `name:"admin"`
	HealthHandler  *apihandler.HealthHandler
	VersionHandler *apihandler.VersionHandler
}

type adminServerParams struct {
	dig.In
	Cfg    *config.Config
	Logger *slog.Logger
	Router router.ServerRouter `name:"admin"`
}

func ServerAdmin(c *container.Container) error {
	if err := c.Provide(adminTransport, dig.Name("admin")); err != nil {
		return err
	}
	if err := c.Provide(
		func(p adminRouterParams) router.ServerRouter {
			return router.NewAdminRouter(p.Transport, p.HealthHandler, p.VersionHandler)
		},
		dig.Name("admin"),
	); err != nil {
		return err
	}
	return c.Provide(
		func(p adminServerParams) server.Server {
			addr := fmt.Sprintf(":%d", p.Cfg.Server.AdminPort)
			return server.NewHTTPServer("admin", addr, p.Cfg.Server, p.Logger, []router.ServerRouter{p.Router})
		},
		dig.Name("admin"),
	)
}
