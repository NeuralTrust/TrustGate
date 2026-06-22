// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"log/slog"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
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
