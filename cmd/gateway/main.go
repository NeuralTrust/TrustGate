package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/NeuralTrust/TrustGate/pkg/app/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	"github.com/NeuralTrust/TrustGate/pkg/app/rule"
	"github.com/NeuralTrust/TrustGate/pkg/app/service"
	"github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	handlers "github.com/NeuralTrust/TrustGate/pkg/handlers/http"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bedrock"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/subscriber"
	infraLogger "github.com/NeuralTrust/TrustGate/pkg/infra/logger"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/server"
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
	})
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize cache with the database's GORM instance
	cacheConfig := common.CacheConfig{
		Host:     cfg.Redis.Host,
		Port:     cfg.Redis.Port,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}
	cacheInstance, err := cache.NewCache(cacheConfig, db.DB)
	if err != nil {
		logger.Fatalf("Failed to initialize cache: %v", err)
	}

	bedrockClient, err := bedrock.NewClient(cfg.AWS, logger)
	if err != nil {
		logger.Fatalf("failed to initialize bedrock client: %v", err)
	}

	pluginManager := plugins.NewManager(cfg, cacheInstance, logger, bedrockClient)

	initializeMemoryCache(cacheInstance)

	// repository
	repo := database.NewRepository(db.DB, logger, cacheInstance)
	upstreamRepository := repository.NewUpstreamRepository(db.DB)
	serviceRepository := repository.NewServiceRepository(db.DB)
	apiKeyRepository := repository.NewApiKeyRepository(db.DB)

	// service
	upstreamFinder := upstream.NewFinder(upstreamRepository, cacheInstance, logger)
	serviceFinder := service.NewFinder(serviceRepository, cacheInstance, logger)
	apiKeyFinder := apikey.NewFinder(apiKeyRepository, cacheInstance, logger)
	updateGatewayCache := gateway.NewUpdateGatewayCache(cacheInstance)
	getGatewayCache := gateway.NewGetGatewayCache(cacheInstance)
	validatePlugin := plugin.NewValidatePlugin(pluginManager)
	validateRule := rule.NewValidateRule(validatePlugin)

	// redis publisher
	redisPublisher := infraCache.NewRedisEventPublisher(cacheInstance)
	redisListener := infraCache.NewRedisEventListener(logger, cacheInstance)

	// subscribers
	deleteGatewaySubscriber := subscriber.NewDeleteGatewayCacheEventSubscriber(logger, cacheInstance)
	deleteRulesSubscriber := subscriber.NewDeleteRulesEventSubscriber(logger, cacheInstance)
	deleteServiceSubscriber := subscriber.NewDeleteServiceCacheEventSubscriber(logger, cacheInstance)
	deleteUpstreamSubscriber := subscriber.NewDeleteUpstreamCacheEventSubscriber(logger, cacheInstance)
	deleteApiKeySubscriber := subscriber.NewDeleteApiKeyCacheEventSubscriber(logger, cacheInstance)
	updateGatewaySubscriber := subscriber.NewUpdateGatewayCacheEventSubscriber(logger, updateGatewayCache, cacheInstance)
	updateUpstreamSubscriber := subscriber.NewUpdateUpstreamCacheEventSubscriber(logger, cacheInstance, upstreamRepository)
	updateServiceSubscriber := subscriber.NewUpdateServiceCacheEventSubscriber(logger, cacheInstance, serviceRepository)

	infraCache.RegisterEventSubscriber[event.DeleteGatewayCacheEvent](redisListener, deleteGatewaySubscriber)
	infraCache.RegisterEventSubscriber[event.DeleteRulesCacheEvent](redisListener, deleteRulesSubscriber)
	infraCache.RegisterEventSubscriber[event.DeleteServiceCacheEvent](redisListener, deleteServiceSubscriber)
	infraCache.RegisterEventSubscriber[event.DeleteUpstreamCacheEvent](redisListener, deleteUpstreamSubscriber)
	infraCache.RegisterEventSubscriber[event.DeleteApiKeyCacheEvent](redisListener, deleteApiKeySubscriber)
	infraCache.RegisterEventSubscriber[event.UpdateGatewayCacheEvent](redisListener, updateGatewaySubscriber)
	infraCache.RegisterEventSubscriber[event.UpdateUpstreamCacheEvent](redisListener, updateUpstreamSubscriber)
	infraCache.RegisterEventSubscriber[event.UpdateServiceCacheEvent](redisListener, updateServiceSubscriber)

	//middleware
	middlewareTransport := middleware.Transport{
		AuthMiddleware:    middleware.NewAuthMiddleware(logger, apiKeyFinder, false),
		GatewayMiddleware: middleware.NewGatewayMiddleware(logger, cacheInstance, repo, cfg.Server.BaseDomain),
		MetricsMiddleware: middleware.NewMetricsMiddleware(logger),
	}

	// Handler Transport
	handlerTransport := handlers.HandlerTransport{
		// Proxy
		ForwardedHandler: handlers.NewForwardedHandler(
			logger, repo, cacheInstance, upstreamFinder, serviceFinder, cfg.Providers.Providers, pluginManager,
		),
		// Gateway
		CreateGatewayHandler: handlers.NewCreateGatewayHandler(logger, repo, updateGatewayCache),
		ListGatewayHandler:   handlers.NewListGatewayHandler(logger, repo, updateGatewayCache),
		GetGatewayHandler:    handlers.NewGetGatewayHandler(logger, repo, getGatewayCache, updateGatewayCache),
		UpdateGatewayHandler: handlers.NewUpdateGatewayHandler(logger, repo, pluginManager, redisPublisher),
		DeleteGatewayHandler: handlers.NewDeleteGatewayHandler(logger, repo, redisPublisher),
		// Upstream
		CreateUpstreamHandler: handlers.NewCreateUpstreamHandler(logger, repo, cacheInstance),
		ListUpstreamHandler:   handlers.NewListUpstreamHandler(logger, repo, cacheInstance),
		GetUpstreamHandler:    handlers.NewGetUpstreamHandler(logger, repo, cacheInstance, upstreamFinder),
		UpdateUpstreamHandler: handlers.NewUpdateUpstreamHandler(logger, repo, redisPublisher),
		DeleteUpstreamHandler: handlers.NewDeleteUpstreamHandler(logger, repo, redisPublisher),
		// Service
		CreateServiceHandler: handlers.NewCreateServiceHandler(logger, repo, cacheInstance),
		ListServicesHandler:  handlers.NewListServicesHandler(logger, repo),
		GetServiceHandler:    handlers.NewGetServiceHandler(logger, serviceRepository, cacheInstance),
		UpdateServiceHandler: handlers.NewUpdateServiceHandler(logger, repo, redisPublisher),
		DeleteServiceHandler: handlers.NewDeleteServiceHandler(logger, repo, redisPublisher),
		// Rule
		CreateRuleHandler: handlers.NewCreateRuleHandler(logger, repo, validateRule),
		ListRulesHandler:  handlers.NewListRulesHandler(logger, repo, cacheInstance),
		UpdateRuleHandler: handlers.NewUpdateRuleHandler(logger, repo, cacheInstance, validateRule, redisPublisher),
		DeleteRuleHandler: handlers.NewDeleteRuleHandler(logger, repo, cacheInstance, redisPublisher),
		// APIKey
		CreateAPIKeyHandler: handlers.NewCreateAPIKeyHandler(logger, repo, cacheInstance),
		ListAPIKeysHandler:  handlers.NewListAPIKeysHandler(logger, repo),
		GetAPIKeyHandler:    handlers.NewGetAPIKeyHandler(logger, cacheInstance),
		DeleteAPIKeyHandler: handlers.NewDeleteAPIKeyHandler(logger, repo, redisPublisher),
	}

	// Create and initialize the server
	adminServerDI := server.AdminServerDI{
		MiddlewareTransport: middlewareTransport,
		HandlerTransport:    handlerTransport,
		Config:              cfg,
		Logger:              logger,
		Cache:               cacheInstance,
	}

	proxyServerDI := server.ProxyServerDI{
		MiddlewareTransport: middlewareTransport,
		HandlerTransport:    handlerTransport,
		Config:              cfg,
		Logger:              logger,
		Cache:               cacheInstance,
	}

	if getServerType() == "proxy" {
		go func() {
			fmt.Println("starting listening redis events...")
			redisListener.Listen(ctx, channel.GatewayEventsChannel)
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

func initializeMemoryCache(cacheInstance *cache.Cache) {
	// memoryCache
	_ = cacheInstance.CreateTTLMap(cache.GatewayTTLName, common.GatewayCacheTTL)
	_ = cacheInstance.CreateTTLMap(cache.RulesTTLName, common.RulesCacheTTL)
	_ = cacheInstance.CreateTTLMap(cache.PluginTTLName, common.PluginCacheTTL)
	_ = cacheInstance.CreateTTLMap(cache.ServiceTTLName, common.ServiceCacheTTL)
	_ = cacheInstance.CreateTTLMap(cache.UpstreamTTLName, common.UpstreamCacheTTL)
	_ = cacheInstance.CreateTTLMap(cache.ApiKeyTTLName, common.ApiKeyCacheTTL)
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
