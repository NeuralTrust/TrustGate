package server

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/prometheus"
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
	}
)

func NewProxyServer(di ProxyServerDI) *ProxyServer {
	if di.Config.Metrics.Enabled {
		metricsConfig := prometheus.MetricsConfig{
			EnableLatency:         di.Config.Metrics.EnableLatency,
			EnableUpstreamLatency: di.Config.Metrics.EnableUpstream,
			EnableConnections:     di.Config.Metrics.EnableConnections,
			EnablePerRoute:        di.Config.Metrics.EnablePerRoute,
		}
		prometheus.Initialize(metricsConfig)
	}

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
