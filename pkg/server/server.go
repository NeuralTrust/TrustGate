package server

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/database"
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
	router         *gin.Engine
	metricsStarted bool
}

func init() {
	// Set Gin mode to release by default
	gin.SetMode(gin.ReleaseMode)
	// Disable Gin's default logging globally
	gin.DefaultWriter = io.Discard
}

func NewBaseServer(config *config.Config, cache *cache.Cache, repo *database.Repository, logger *logrus.Logger) *BaseServer {
	// Create a new Gin router with default middleware
	router := gin.New()

	// Disable all Gin logging middleware
	router.Use(gin.Recovery())

	return &BaseServer{
		config: config,
		cache:  cache,
		repo:   repo,
		logger: logger,
		router: router,
	}
}

// setupHealthCheck adds a health check endpoint to the server
func (s *BaseServer) setupHealthCheck() {
	s.router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
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
	return s.router.Run(addr)
}

func (s *BaseServer) setupMetricsEndpoint() {
	// Only start metrics server once
	if s.metricsStarted {
		return
	}
	s.metricsStarted = true

	// Create a new router for metrics
	metricsRouter := gin.New()
	metricsRouter.Use(gin.Recovery())

	// Add prometheus metrics endpoint
	metricsRouter.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Start metrics server on a different port
	go func() {
		if err := metricsRouter.Run(fmt.Sprintf(":%d", s.config.Server.MetricsPort)); err != nil {
			if !strings.Contains(err.Error(), "address already in use") {
				s.logger.WithError(err).Error("Failed to start metrics server")
			}
		}
	}()
}

// InitializeMetrics sets up the metrics endpoint if needed
func (s *BaseServer) InitializeMetrics() {
	// Only initialize metrics if this is not a proxy server
	if !s.isProxyServer() {
		s.setupMetricsEndpoint()
	}
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
