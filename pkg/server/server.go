package server

import (
	"fmt"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"strings"
	"time"
)

// Server interface defines the common behavior for all servers
type Server interface {
	Run() error
}

type BaseServer struct {
	config         *config.Config
	cache          *cache.Cache
	repo           *database.Repository
	logger         *logrus.Logger
	router         *fiber.App
	metricsStarted bool
}

func NewBaseServer(config *config.Config, cache *cache.Cache, repo *database.Repository, logger *logrus.Logger) *BaseServer {
	r := fiber.New(fiber.Config{
		Prefork:               true,
		DisableStartupMessage: true,
	})
	return &BaseServer{
		config: config,
		cache:  cache,
		repo:   repo,
		logger: logger,
		router: r,
	}
}

func healthHandler(ctx *fasthttp.RequestCtx) {

}

// setupHealthCheck adds a health check endpoint to the server
func (s *BaseServer) setupHealthCheck() {
	s.router.Get("/health", func(ctx *fiber.Ctx) error {
		return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

}

// isProxyServer returns true if this is a proxy server instance
func (s *BaseServer) isProxyServer() bool {
	return false // Base implementation returns false
}

// runServer is a helper method to start the server
func (s *BaseServer) runServer(addr string) error {
	// Only set up health check if this isn't a proxy server
	if !s.isProxyServer() {
		s.setupHealthCheck()
	}
	return s.router.Listen(addr)
}

func (s *BaseServer) setupMetricsEndpoint() {
	// Ensure metrics server starts only once
	if s.metricsStarted {
		return
	}
	s.metricsStarted = true

	metricsApp := fiber.New()

	metricsApp.Use(recover.New())

	metricsApp.Get("/metrics", func(c *fiber.Ctx) error {
		handler := fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())
		handler(c.Context())
		return nil
	})

	// Start metrics server on a different port
	go func() {
		port := s.config.Server.MetricsPort
		addr := fmt.Sprintf(":%d", port)
		if err := metricsApp.Listen(addr); err != nil {
			if !strings.Contains(err.Error(), "address already in use") {
				s.logger.WithError(err).Error("Failed to start metrics server")
			}
		}
	}()
}

// Run implements the Server interface
func (s *BaseServer) Run() error {
	var port int
	if s.isProxyServer() {
		port = s.config.Server.ProxyPort
	} else {
		port = s.config.Server.AdminPort
	}
	return s.runServer(fmt.Sprintf(":%d", port))
}
