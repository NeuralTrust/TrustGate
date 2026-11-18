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
	"github.com/NeuralTrust/TrustGate/pkg/infra/bootlog"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
)

type httpServer struct {
	*BaseServer
	mu sync.Mutex
	// tlsCert and tlsKey, when set, are the PEM files the server serves HTTPS
	// with instead of plain HTTP.
	tlsCert, tlsKey string
}

// HTTPServerOption tunes an HTTP server built by NewHTTPServer.
type HTTPServerOption func(*httpServer)

// WithTLS serves HTTPS with the PEM certificate chain and key at these paths.
// Fiber's listener requires TLS 1.2 or later. Empty paths leave the server on
// plain HTTP.
func WithTLS(certFile, keyFile string) HTTPServerOption {
	return func(s *httpServer) {
		s.tlsCert, s.tlsKey = certFile, keyFile
	}
}

func NewHTTPServer(
	name, addr string,
	cfg config.ServerConfig,
	logger *slog.Logger,
	routers []router.ServerRouter,
	opts ...HTTPServerOption,
) Server {
	s := &httpServer{
		BaseServer: NewBaseServer(name, addr, cfg, logger).WithRouters(routers...),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *httpServer) Run() error {
	tls := s.tlsCert != "" && s.tlsKey != ""
	s.logger.Info(bootlog.HTTPStart(s.Name),
		slog.String("server", s.Name),
		slog.String("addr", s.Addr),
		slog.Bool("tls", tls),
	)
	if tls {
		return s.Router.ListenTLS(s.Addr, s.tlsCert, s.tlsKey)
	}
	return s.Router.Listen(s.Addr)
}

func (s *httpServer) Shutdown() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logger.Info(bootlog.HTTPShutdown(s.Name), slog.String("server", s.Name))
	if err := s.Router.Shutdown(); err != nil {
		s.logger.Warn("HTTP server shutdown error",
			slog.String("server", s.Name),
			slog.String("error", err.Error()),
		)
		return err
	}
	s.logger.Info(bootlog.HTTPStopped(s.Name), slog.String("server", s.Name))
	return nil
}
