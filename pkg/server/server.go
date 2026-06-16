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

// Package server hosts the shared HTTP server lifecycle for admin and proxy.
package server

import (
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/server/router"
	"github.com/gofiber/fiber/v2"
)

// Server is the lifecycle contract for an HTTP listener.
type Server interface {
	Run() error
	Shutdown() error
}

type BaseServer struct {
	Name   string
	Addr   string
	Router *fiber.App
	logger *slog.Logger
}

func NewBaseServer(name, addr string, cfg config.ServerConfig, logger *slog.Logger) *BaseServer {
	r := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ReduceMemoryUsage:     true,
		Network:               fiber.NetworkTCP,
		EnablePrintRoutes:     false,
		BodyLimit:             8 * 1024 * 1024,
		ReadTimeout:           cfg.ReadTimeout,
		WriteTimeout:          cfg.WriteTimeout,
		IdleTimeout:           cfg.IdleTimeout,
		Concurrency:           16384,
		// The gateway must read the full request body on the hot path (stream
		// detection, cross-format adaptation, session/metrics extraction), so
		// streaming the request body provides no benefit and risks c.Body()
		// returning an empty/partial payload if the stream is consumed once.
		// Buffer the whole body up front instead, bounded by BodyLimit.
		StreamRequestBody: false,
	})

	r.Server().MaxConnsPerIP = 1024
	r.Server().ReadBufferSize = 8192
	r.Server().WriteBufferSize = 8192
	r.Server().GetOnly = false
	r.Server().NoDefaultServerHeader = true
	r.Server().NoDefaultDate = true
	r.Server().NoDefaultContentType = true

	return &BaseServer{Name: name, Addr: addr, Router: r, logger: logger}
}

func (s *BaseServer) WithRouters(routers ...router.ServerRouter) *BaseServer {
	for _, rt := range routers {
		if err := rt.BuildRoutes(s.Router); err != nil {
			s.logger.Error("failed to build routes",
				slog.String("server", s.Name),
				slog.String("error", err.Error()),
			)
		}
	}
	return s
}
