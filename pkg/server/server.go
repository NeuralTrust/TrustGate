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
	"context"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"github.com/gofiber/fiber/v2"
)

// Server is the lifecycle contract for an HTTP listener.
type Server interface {
	Run() error
	Shutdown() error
}

// ShutdownHook releases a resource that keeps connections busy, before the
// router itself is asked to shut down.
type ShutdownHook func(ctx context.Context) error

// shutdownHookBudget bounds the hooks as a whole. It has to stay well under the
// orchestrator's termination grace period, because whatever the hooks do not
// finish is followed by a router shutdown that has its own wait.
const shutdownHookBudget = 5 * time.Second

type BaseServer struct {
	Name   string
	Addr   string
	Router *fiber.App
	logger *slog.Logger
	hooks  []ShutdownHook
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

// WithShutdownHooks registers hooks run at the top of Shutdown, in order. Nil
// hooks are dropped so a disabled feature can pass one unconditionally.
func (s *BaseServer) WithShutdownHooks(hooks ...ShutdownHook) *BaseServer {
	for _, hook := range hooks {
		if hook != nil {
			s.hooks = append(s.hooks, hook)
		}
	}
	return s
}

// runShutdownHooks runs every hook under one shared budget. A hook that fails or
// times out is logged and the next one still runs: the router shutdown that
// follows must not be skipped.
func (s *BaseServer) runShutdownHooks() {
	if len(s.hooks) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownHookBudget)
	defer cancel()
	for _, hook := range s.hooks {
		if err := hook(ctx); err != nil {
			s.logger.Warn("shutdown hook did not complete",
				slog.String("server", s.Name),
				slog.String("error", err.Error()),
			)
		}
	}
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
