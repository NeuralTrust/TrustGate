package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	handlers "github.com/NeuralTrust/TrustGate/pkg/handlers/http"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type (
	ProxyServerDI struct {
		Config              *config.Config
		Cache               *cache.Cache
		Logger              *logrus.Logger
		MiddlewareTransport middleware.Transport
		HandlerTransport    handlers.HandlerTransport
	}
	ProxyServer struct {
		*BaseServer
		middlewareTransport middleware.Transport
		handlerTransport    handlers.HandlerTransport
	}
)

const (
	HealthPath = "/health"
	PingPath   = "/__/ping"
)

func NewProxyServer(di ProxyServerDI) *ProxyServer {
	metricsConfig := metrics.MetricsConfig{
		EnableLatency:         di.Config.Metrics.EnableLatency,
		EnableUpstreamLatency: di.Config.Metrics.EnableUpstream,
		EnableConnections:     di.Config.Metrics.EnableConnections,
		EnablePerRoute:        di.Config.Metrics.EnablePerRoute,
	}
	metrics.Initialize(metricsConfig)

	s := &ProxyServer{
		BaseServer:          NewBaseServer(di.Config, di.Cache, di.Logger),
		middlewareTransport: di.MiddlewareTransport,
		handlerTransport:    di.HandlerTransport,
	}

	s.BaseServer.setupMetricsEndpoint()
	return s
}

func (s *ProxyServer) Run() error {

	s.router.Get(HealthPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	s.router.Get(PingPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"message": "pong",
		})
	})

	// Register the main handler for all non-system routes
	s.router.Use(
		s.middlewareTransport.GatewayMiddleware.Middleware(),
		s.middlewareTransport.AuthMiddleware.Middleware(),
		s.middlewareTransport.MetricsMiddleware.Middleware(),
		s.handlerTransport.ForwardedHandler.Handle,
	)

	s.logger.WithField("addr", s.config.Server.ProxyPort).Info("Starting proxy server")
	return s.router.Listen(fmt.Sprintf(":%d", s.config.Server.ProxyPort))
}

func (s *ProxyServer) Shutdown() error {
	return s.router.Shutdown()
}
