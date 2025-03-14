package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/NeuralTrust/TrustGate/pkg/dependency_container"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	infraLogger "github.com/NeuralTrust/TrustGate/pkg/infra/logger"
	"github.com/NeuralTrust/TrustGate/pkg/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/server"
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
	if err := config.Load("../../config"); err != nil {
		logger.Fatalf("Failed to load config: %v", err)
	}
	cfg := config.GetConfig()

	// Initialize database
	db, err := database.NewDB(&database.Config{
		Host:     cfg.Database.Host,
		Port:     cfg.Database.Port,
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
		DBName:   cfg.Database.DBName,
		SSLMode:  cfg.Database.SSLMode,
	}, database.GetRegisteredModels())
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	lbFactory := loadbalancer.NewBaseFactory()

	container, err := dependency_container.NewContainer(
		cfg,
		logger,
		db,
		lbFactory,
		event.GetEventsRegistry(),
		initializeMemoryCache(),
	)
	if err != nil {
		logger.Fatalf("Failed to initialize container: %v", err)
	}

	proxyTransport := middleware.NewTransport(
		container.GatewayMiddleware,
		container.AuthMiddleware,
		container.MetricsMiddleware,
		container.PluginMiddleware,
	)

	//routers
	proxyRouter := router.NewProxyRouter(proxyTransport, container.HandlerTransport)
	adminRouter := router.NewAdminRouter(container.HandlerTransport)

	// Create and initialize the server
	adminServerDI := server.AdminServerDI{
		Config:  cfg,
		Logger:  logger,
		Cache:   container.Cache,
		Routers: []router.ServerRouter{adminRouter},
	}

	proxyServerDI := server.ProxyServerDI{
		Config:  cfg,
		Logger:  logger,
		Cache:   container.Cache,
		Routers: []router.ServerRouter{proxyRouter},
	}

	if getServerType() == "proxy" {
		go func() {
			fmt.Println("starting listening redis events...")
			container.RedisListener.Listen(ctx, channel.GatewayEventsChannel)
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
	if err := srv.Shutdown(); err != nil {
		fmt.Println("error shutting down server:", err)
		os.Exit(1)
	}
	fmt.Println("server gracefully stopped")
}

func initializeMemoryCache() func(cacheInstance *cache.Cache) {
	// memoryCache
	return func(cacheInstance *cache.Cache) {
		_ = cacheInstance.CreateTTLMap(cache.GatewayTTLName, common.GatewayCacheTTL)
		_ = cacheInstance.CreateTTLMap(cache.RulesTTLName, common.RulesCacheTTL)
		_ = cacheInstance.CreateTTLMap(cache.PluginTTLName, common.PluginCacheTTL)
		_ = cacheInstance.CreateTTLMap(cache.ServiceTTLName, common.ServiceCacheTTL)
		_ = cacheInstance.CreateTTLMap(cache.UpstreamTTLName, common.UpstreamCacheTTL)
		_ = cacheInstance.CreateTTLMap(cache.ApiKeyTTLName, common.ApiKeyCacheTTL)
	}
}

func getServerType() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return "proxy"
}

func initializeServer(
	proxyServerDi server.ProxyServerDI,
	adminServerDi server.AdminServerDI,
) server.Server {
	serverType := getServerType()

	switch serverType {
	case "admin":
		return server.NewAdminServer(adminServerDi)
	default:
		return server.NewProxyServer(proxyServerDi)
	}
}
