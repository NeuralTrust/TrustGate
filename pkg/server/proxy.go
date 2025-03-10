package server

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	handlers "github.com/NeuralTrust/TrustGate/pkg/handlers/http"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"github.com/sirupsen/logrus"
)

type (
	ProxyServerDI struct {
		Config  *config.Config
		Cache   *cache.Cache
		Logger  *logrus.Logger
		Routers []router.ServerRouter
	}
	ProxyServer struct {
		*BaseServer
		middlewareTransport middleware.Transport
		handlerTransport    handlers.HandlerTransport
	}
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
		BaseServer: NewBaseServer(di.Config, di.Cache, di.Logger).WithRouters(di.Routers...),
	}
	s.BaseServer.setupMetricsEndpoint()
	return s
}

func (s *ProxyServer) Run() error {
	s.logger.WithField("addr", s.config.Server.ProxyPort).Info("Starting proxy server")
	return s.router.Listen(fmt.Sprintf(":%d", s.config.Server.ProxyPort))
}

func (s *ProxyServer) Shutdown() error {
	return s.router.Shutdown()
}
