package server

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/config"
)

type (
	AdminServerDI struct {
		Routers []router.ServerRouter
		Config  *config.Config
		Cache   *cache.Cache
		Logger  *logrus.Logger
	}
	AdminServer struct {
		*BaseServer
	}
)

func NewAdminServer(di AdminServerDI) *AdminServer {
	return &AdminServer{
		BaseServer: NewBaseServer(di.Config, di.Cache, di.Logger).WithRouters(di.Routers...),
	}
}

func (s *AdminServer) Run() error {
	// Set up routes
	s.setupHealthCheck()
	// Start the server
	addr := fmt.Sprintf(":%d", s.config.Server.AdminPort)
	s.logger.WithField("addr", addr).Info("Starting admin server")
	return s.router.Listen(addr)
}

func (s *AdminServer) Shutdown() error {
	return s.router.Shutdown()
}
