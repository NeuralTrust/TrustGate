package server

import (
	"log/slog"
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/server/router"
)

type httpServer struct {
	*BaseServer
	mu sync.Mutex
}

func NewHTTPServer(
	name, addr string,
	cfg config.ServerConfig,
	logger *slog.Logger,
	routers []router.ServerRouter,
) Server {
	return &httpServer{
		BaseServer: NewBaseServer(name, addr, cfg, logger).WithRouters(routers...),
	}
}

func (s *httpServer) Run() error {
	s.logger.Info("HTTP server starting",
		slog.String("server", s.Name),
		slog.String("addr", s.Addr),
	)
	return s.Router.Listen(s.Addr)
}

func (s *httpServer) Shutdown() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logger.Info("shutting down HTTP server", slog.String("server", s.Name))
	if err := s.Router.Shutdown(); err != nil {
		s.logger.Warn("HTTP server shutdown error",
			slog.String("server", s.Name),
			slog.String("error", err.Error()),
		)
		return err
	}
	s.logger.Info("HTTP server stopped", slog.String("server", s.Name))
	return nil
}
