package server

import (
	"crypto/tls"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/prometheus"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"github.com/sirupsen/logrus"
)

const ProxyServerName = "proxy"

type (
	ProxyServerDI struct {
		Config  *config.Config
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
		BaseServer: NewBaseServer(di.Config, di.Logger).WithRouters(di.Routers...),
	}
	s.setupMetricsEndpoint()
	return s
}

func (s *ProxyServer) Run() error {
	addr := fmt.Sprintf(":%d", s.Config.Server.ProxyPort)
	s.Logger.WithField("addr", addr).Info("🚀 starting proxy server")
	if s.Config.TLS.Disabled {
		return s.Router.Listen(addr)
	}
	tlsConfig, err := config.BuildTLSConfig(&s.Config.TLS)
	if err != nil {
		s.Logger.WithError(err).Error("failed to build TLS config")
		return err
	}
	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		s.Logger.WithError(err).Error("failed to start TLS listener")
		return err
	}

	if s.Config.TLS.EnableMTLS {
		s.Logger.Info("mTLS enabled — serving HTTPS with mutual authentication")
	} else {
		s.Logger.Info("TLS enabled — serving HTTPS with custom certificates")
	}
	return s.Router.Listener(ln)
}

func (s *ProxyServer) Shutdown() error {
	return s.Router.Shutdown()
}
