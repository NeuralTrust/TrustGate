package server

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/config"
)

const AdminServerName = "admin"

type (
	AdminServerDI struct {
		Routers []router.ServerRouter
		Config  *config.Config
		Logger  *logrus.Logger
	}
	AdminServer struct {
		*BaseServer
	}
)

func NewAdminServer(di AdminServerDI) *AdminServer {
	return &AdminServer{
		BaseServer: NewBaseServer(di.Config, di.Logger).WithRouters(di.Routers...),
	}
}

func (s *AdminServer) Run() error {
	s.setupHealthCheck()
	addr := fmt.Sprintf(":%d", s.Config.Server.AdminPort)
	s.Logger.WithField("addr", addr).Info("🚀 starting admin server")
	return s.Router.Listen(addr)
}

func (s *AdminServer) Shutdown() error {
	return s.Router.Shutdown()
}
