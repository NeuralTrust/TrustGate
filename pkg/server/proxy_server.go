package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	handlers "github.com/NeuralTrust/TrustGate/pkg/handlers/http"
	"github.com/NeuralTrust/TrustGate/pkg/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

type (
	ProxyServerDI struct {
		Config              *config.Config
		Cache               *cache.Cache
		Logger              *logrus.Logger
		MiddlewareTransport middleware.Transport
		HandlerTransport    handlers.HandlerTransport
	}
	ProxyServer struct {
		*BaseServer
		middlewareTransport middleware.Transport
		handlerTransport    handlers.HandlerTransport
		gatewayCache        *common.TTLMap
		rulesCache          *common.TTLMap
		pluginCache         *common.TTLMap
	}
)

// Cache TTLs
const (
	GatewayCacheTTL = 1 * time.Hour
	RulesCacheTTL   = 5 * time.Minute
	PluginCacheTTL  = 30 * time.Minute
)

const (
	HealthPath      = "/health"
	AdminHealthPath = "/__/health"
	PingPath        = "/__/ping"
)

func NewProxyServer(di ProxyServerDI) *ProxyServer {
	metricsConfig := metrics.MetricsConfig{
		EnableLatency:         di.Config.Metrics.EnableLatency,
		EnableUpstreamLatency: di.Config.Metrics.EnableUpstream,
		EnableConnections:     di.Config.Metrics.EnableConnections,
		EnablePerRoute:        di.Config.Metrics.EnablePerRoute,
	}
	metrics.Initialize(metricsConfig)

	gatewayCache := di.Cache.CreateTTLMap("gateway", GatewayCacheTTL)
	rulesCache := di.Cache.CreateTTLMap("rules", RulesCacheTTL)
	pluginCache := di.Cache.CreateTTLMap("plugin", PluginCacheTTL)

	s := &ProxyServer{
		BaseServer:          NewBaseServer(di.Config, di.Cache, di.Logger),
		middlewareTransport: di.MiddlewareTransport,
		handlerTransport:    di.HandlerTransport,
		gatewayCache:        gatewayCache,
		rulesCache:          rulesCache,
		pluginCache:         pluginCache,
	}

	s.BaseServer.setupMetricsEndpoint()

	// Subscribe to gateway events
	go s.subscribeToEvents()

	return s
}

func (s *ProxyServer) Run() error {
	s.router.Get(AdminHealthPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	s.router.Get(HealthPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	s.router.Get(PingPath, func(ctx *fiber.Ctx) error {
		return ctx.Status(http.StatusOK).JSON(fiber.Map{
			"message": "pong",
		})
	})

	s.router.Get("/debug/pprof/*", func(c *fiber.Ctx) error {
		pprofHandler := fasthttpadaptor.NewFastHTTPHandler(http.DefaultServeMux)
		pprofHandler(c.Context())
		return nil
	})

	// Register the main handler for all non-system routes
	s.router.Use(
		s.middlewareTransport.GatewayMiddleware.Middleware(),
		s.middlewareTransport.AuthMiddleware.Middleware(),
		s.middlewareTransport.MetricsMiddleware.Middleware(),
		s.handlerTransport.ForwardedHandler.Handle,
	)

	s.logger.WithField("addr", s.config.Server.ProxyPort).Info("Starting proxy server")
	return s.router.Listen(fmt.Sprintf(":%d", s.config.Server.ProxyPort))
}

func (s *ProxyServer) subscribeToEvents() {
	rdb := s.cache.Client()
	pubsub := rdb.Subscribe(context.Background(), "gateway_events")
	defer pubsub.Close()

	// Listen for messages
	ch := pubsub.Channel()
	for msg := range ch {
		var event map[string]string
		if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
			s.logger.WithError(err).Error("Failed to unmarshal event")
			continue
		}
		if event["type"] == "cache_invalidation" {
			gatewayID := event["gatewayID"]
			if err := s.invalidateGatewayCache(context.Background(), gatewayID); err != nil {
				s.logger.WithError(err).Error("Failed to invalidate gateway cache")
			}
		}
	}
}

// InvalidateGatewayCache removes the gateway data from both memory and Redis cache
func (s *ProxyServer) invalidateGatewayCache(ctx context.Context, gatewayID string) error {
	s.logger.WithFields(logrus.Fields{
		"gatewayID": gatewayID,
	}).Debug("invalidating gateway cache")

	// Remove from memory cache
	s.gatewayCache.Delete(gatewayID)

	// Remove from Redis cache
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	if err := s.cache.Delete(ctx, rulesKey); err != nil {
		s.logger.WithError(err).Warn("Failed to delete rules from Redis cache")
	}
	return nil
}

func (s *ProxyServer) Shutdown() error {
	return s.router.Shutdown()
}
