// @title TrustGate
// @version v1.6.10
// @contact.name NeuralTrust
// @contact.url https://neuraltrust.ai/contact
// @contact.email support@neuraltrust.ai
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/dependency_container"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	infraLogger "github.com/NeuralTrust/TrustGate/pkg/infra/logger"
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/migrations"
	"github.com/NeuralTrust/TrustGate/pkg/server"
	"github.com/NeuralTrust/TrustGate/pkg/server/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
	"github.com/joho/godotenv"
)

func main() {
	ctx := context.Background()
	serverType := getServerType()
	envFile := os.Getenv("ENV_FILE")

	if envFile == "" {
		envFile = ".env"
	}

	err := godotenv.Load(envFile)
	if err != nil {
		log.Println("no .env file found, using system environment variables")
	}
	logger := infraLogger.NewLogger(serverType)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database
	db, err := database.NewDB(logger, &database.Config{
		Host:     cfg.Database.Host,
		Port:     cfg.Database.Port,
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
		DBName:   cfg.Database.DBName,
		SSLMode:  cfg.Database.SSLMode,
	})
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}
	defer func() { _ = db.Close() }()

	eventsChannel := channel.GatewayEventsChannel
	if cfg.Redis.EventsChannel != "" {
		eventsChannel = channel.Channel(cfg.Redis.EventsChannel)
	}

	container, err := dependency_container.NewContainer(dependency_container.ContainerDI{
		Cfg:                           cfg,
		Logger:                        logger,
		DB:                            db,
		EventsRegistry:                event.GetEventsRegistry(),
		InitializeMemoryCache:         initializeMemoryCache(),
		InitializeLoadBalancerFactory: loadbalancer.NewBaseFactory,
		InitializeCachePublisher:      cache.NewRedisEventPublisher,
		EventsChannel:                 eventsChannel,
	})
	if err != nil {
		logger.Fatalf("Failed to initialize container: %v", err)
	}
	defer func() {
		if err := container.AuditLogsService.Close(); err != nil {
			logger.WithError(err).Error("failed to close audit logs service")
		}
	}()

	proxyTransport := middleware.NewTransport(
		container.PanicRecoverMiddleware,
		container.CORSGlobalMiddleware,
		container.AuthMiddleware,
		container.MetricsMiddleware,
		container.PluginMiddleware,
		container.FingerPrintMiddleware,
		container.SecurityMiddleware,
		container.WebSocketMiddleware,
		container.SessionMiddleware,
	)

	//routers
	proxyRouter := router.NewProxyRouter(
		proxyTransport,
		container.HandlerTransport,
		container.WSHandlerTransport,
		cfg,
	)

	adminTransport := middleware.NewTransport(
		container.PanicRecoverMiddleware,
		container.AdminAuthMiddleware,
	)
	adminRouter := router.NewAdminRouter(adminTransport, container.HandlerTransport)

	// Create and initialize the server
	adminServerDI := server.AdminServerDI{
		Config:  cfg,
		Logger:  logger,
		Routers: []router.ServerRouter{adminRouter},
	}

	proxyServerDI := server.ProxyServerDI{
		Config:  cfg,
		Logger:  logger,
		Routers: []router.ServerRouter{proxyRouter},
	}
	if getServerType() == server.ProxyServerName {
		go func() {
			logger.WithField("channel", eventsChannel).Info("starting listening redis events...")
			container.MetricsWorker.StartWorkers(5)
			container.RedisListener.Listen(ctx, eventsChannel)
		}()
	}

	srv := initializeServer(proxyServerDI, adminServerDI)

	go func() {
		if err := srv.Run(); err != nil {
			logger.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	<-quit
	fmt.Println("shutting down server...")
	container.MetricsWorker.Shutdown()
	if err := srv.Shutdown(); err != nil {
		fmt.Println("error shutting down server:", err)
		os.Exit(1)
	}
	fmt.Println("server gracefully stopped")
}

func initializeMemoryCache() func(cacheInstance cache.Client) {
	// memoryCache
	return func(cacheInstance cache.Client) {
		_ = cacheInstance.CreateTTLMap(cache.GatewayTTLName, common.GatewayCacheTTL)
		_ = cacheInstance.CreateTTLMap(cache.RulesTTLName, common.RulesCacheTTL)
		_ = cacheInstance.CreateTTLMap(cache.PluginTTLName, common.PluginCacheTTL)
		_ = cacheInstance.CreateTTLMap(cache.ServiceTTLName, common.ServiceCacheTTL)
		_ = cacheInstance.CreateTTLMap(cache.UpstreamTTLName, common.UpstreamCacheTTL)
		_ = cacheInstance.CreateTTLMap(cache.ApiKeyTTLName, common.ApiKeyCacheTTL)
		_ = cacheInstance.CreateTTLMap(cache.DataMaskingTTLName, common.PluginCacheTTL)
		_ = cacheInstance.CreateTTLMap(cache.LoadBalancerTTLName, common.LoadBalancerCacheTTL)
	}
}

func getServerType() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return server.ProxyServerName
}

func initializeServer(
	proxyServerDi server.ProxyServerDI,
	adminServerDi server.AdminServerDI,
) server.Server {
	serverType := getServerType()

	switch serverType {
	case server.AdminServerName:
		return server.NewAdminServer(adminServerDi)
	default:
		return server.NewProxyServer(proxyServerDi)
	}
}
