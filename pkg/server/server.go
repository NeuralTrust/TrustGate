package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

const AdminHealthPath = "/__/health"

// Server interface defines the common behavior for all servers
type Server interface {
	Run() error
	Shutdown() error
}

type BaseServer struct {
	Config         *config.Config
	Logger         *logrus.Logger
	Router         *fiber.App
	metricsStarted bool
}

func NewBaseServer(config *config.Config, logger *logrus.Logger) *BaseServer {
	r := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ReduceMemoryUsage:     true,
		Network:               fiber.NetworkTCP,
		EnablePrintRoutes:     false,
		BodyLimit:             8 * 1024 * 1024,
		ReadTimeout:           60 * time.Second,
		WriteTimeout:          60 * time.Second,
		IdleTimeout:           120 * time.Second,
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

	server := &BaseServer{
		Config: config,
		Logger: logger,
		Router: r,
	}
	return server
}

// setupHealthCheck adds a health check endpoint to the server
func (s *BaseServer) setupHealthCheck() {
	s.Router.Get("/health", func(ctx *fiber.Ctx) error {
		return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})
	s.Router.Get(AdminHealthPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	})
}

func (s *BaseServer) WithRouters(routers ...router.ServerRouter) *BaseServer {
	for _, r := range routers {
		err := r.BuildRoutes(s.Router)
		if err != nil {
			s.Logger.WithError(err).Error("failed to build routes")
		}
	}
	return s
}

func (s *BaseServer) setupMetricsEndpoint() {
	if !s.Config.Metrics.Enabled {
		s.Logger.Info("prometheus metrics are disabled by configuration")
		return
	}
	if s.metricsStarted {
		return
	}
	s.metricsStarted = true

	metricsApp := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	metricsApp.Use(recover.New())

	metricsApp.Get("/metrics", func(c *fiber.Ctx) error {
		handler := fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())
		handler(c.Context())
		return nil
	})

	// Start metrics server on a different port
	go func() {
		port := s.Config.Server.MetricsPort
		addr := fmt.Sprintf(":%d", port)
		if err := metricsApp.Listen(addr); err != nil {
			if !strings.Contains(err.Error(), "address already in use") {
				s.Logger.WithError(err).Error("Failed to start metrics server")
			}
		}
	}()
}
