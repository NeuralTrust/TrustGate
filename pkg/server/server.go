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
		StreamRequestBody:     true,
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
