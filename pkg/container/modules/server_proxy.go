package modules

import (
	"fmt"
	"log/slog"

	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	proxyhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/proxy"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/server"
	"github.com/NeuralTrust/AgentGateway/pkg/server/router"
	"go.uber.org/dig"
)

type proxyMiddlewares struct {
	dig.In
	RequestID       *middleware.RequestIDMiddleware
	PanicRecover    *middleware.PanicRecoverMiddleware
	AccessLog       *middleware.AccessLogMiddleware
	SecurityHeaders *middleware.SecurityHeadersMiddleware
	Session         *middleware.SessionMiddleware
	FingerPrint     *middleware.FingerPrintMiddleware
	Auth            *middleware.AuthMiddleware
	Metrics         *middleware.MetricsMiddleware
}

// proxyTransport intentionally omits the gateway-wide CORS middleware: on the
// proxy plane CORS is owned per-route by the `cors` policy plugin, which
// negotiates origins/methods and short-circuits preflight requests. Mounting
// the global middleware here would intercept OPTIONS preflights before the
// plugin runs and apply the gateway-wide defaults instead of the route policy.
func proxyTransport(m proxyMiddlewares) *middleware.Transport {
	return middleware.NewTransport(
		m.RequestID,
		m.SecurityHeaders,
		m.PanicRecover,
		m.AccessLog,
		m.Session,
		m.FingerPrint,
		m.Auth,
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
