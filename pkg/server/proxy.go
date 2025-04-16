package server

import (
	"crypto/tls"
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
	addr := fmt.Sprintf(":%d", s.config.Server.ProxyPort)
	s.logger.WithField("addr", addr).Info("Starting proxy server")
	if s.config.TLS.Disabled {
		return s.router.Listen(addr)
	}
	tlsConfig, err := config.BuildTLSConfig(&s.config.TLS)
	if err != nil {
		s.logger.WithError(err).Error("failed to build TLS config")
		return err
	}
	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		s.logger.WithError(err).Error("failed to start TLS listener")
		return err
	}

	s.logger.Info("TLS enabled — serving HTTPS")
	return s.router.Listener(ln)
}

func (s *ProxyServer) Shutdown() error {
	return s.router.Shutdown()
}
