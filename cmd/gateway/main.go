package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	"github.com/NeuralTrust/TrustGate/pkg/app/rule"
	"github.com/NeuralTrust/TrustGate/pkg/app/service"
	"github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	handlers "github.com/NeuralTrust/TrustGate/pkg/handlers/http"
	infraLogger "github.com/NeuralTrust/TrustGate/pkg/infra/logger"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository"
	"github.com/NeuralTrust/TrustGate/pkg/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/database"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/server"
)

func main() {

	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime: "time",
			logrus.FieldKeyMsg:  "msg",
		},
	})

	// Set log level
	if os.Getenv("LOG_LEVEL") == "debug" {
		logger.SetLevel(logrus.DebugLevel)
	}

	//textHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})
	//asyncHandler := infraLogger.NewAsyncHandler(textHandler, 100)
	//slogger := slog.New(asyncHandler)
	//slog.SetDefault(slogger)
	// Get server type once at the start
	serverType := getServerType()

	// Set up logging to file
	var logFile string
	if serverType == "admin" {
		logFile = "logs/admin.log"
	} else {
		logFile = "logs/proxy.log"
	}

	// Validate and sanitize log file path
	logFile = filepath.Clean(logFile)
	if !strings.HasPrefix(logFile, "logs/") {
		log.Fatalf("Invalid log file path: must be in logs directory")
	}

	// Create logs directory with more restrictive permissions
	if err := os.MkdirAll("logs", 0750); err != nil {
		log.Fatalf("Failed to create logs directory: %v", err)
	}

	// Open log file with more restrictive permissions
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	asyncWriter, err := infraLogger.NewAsyncFileWriter(logFile, 32*1024)
	if err != nil {
		log.Fatalf("Failed to initialize async log writer: %v", err)
	}
	defer asyncWriter.Close()

	// Set the logger output to the file
	logger.SetOutput(asyncWriter)

	asyncConsoleHook := infraLogger.NewAsyncConsoleHook(500)
	defer asyncConsoleHook.Close()

	// In debug mode, add a hook for stdout
	if os.Getenv("LOG_LEVEL") == "debug" {
		logger.AddHook(asyncConsoleHook)
	}

	// Load configuration
	if err := config.Load(); err != nil {
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

	plugins.InitializePlugins(cacheInstance, logger)
	pluginManager := plugins.GetManager()

	// Initialize repository
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
	invalidateCachePublisher := infraCache.NewInvalidationPublisher(cacheInstance)
	invalidateGatewayCache := gateway.NewInvalidateGatewayCache(cacheInstance, invalidateCachePublisher)
	validatePlugin := plugin.NewValidatePlugin()
	validateRule := rule.NewValidateRule(validatePlugin)

	//middleware
	middlewareTransport := middleware.Transport{
		AuthMiddleware:    middleware.NewAuthMiddleware(logger, apiKeyFinder, false),
		GatewayMiddleware: middleware.NewGatewayMiddleware(logger, cacheInstance, repo, cfg.Server.BaseDomain),
		MetricsMiddleware: middleware.NewMetricsMiddleware(logger),
	}

	//handler
	forwardedHandler := handlers.NewForwardedHandler(
		logger,
		repo,
		cacheInstance,
		upstreamFinder,
		serviceFinder,
		cfg.Providers.Providers,
		pluginManager,
	)

	createGatewayHandler := handlers.NewCreateGatewayHandler(logger, repo, updateGatewayCache)
	listGatewayHandler := handlers.NewListGatewayHandler(logger, repo, updateGatewayCache)
	getGatewayHandler := handlers.NewGetGatewayHandler(logger, repo, getGatewayCache, updateGatewayCache)
	updateGatewayHandler := handlers.NewUpdateGatewayHandler(
		logger,
		repo,
		updateGatewayCache,
		invalidateGatewayCache,
		pluginManager,
	)
	deleteGatewayHandler := handlers.NewDeleteGatewayHandler(logger, repo)

	createUpstreamHandler := handlers.NewCreateUpstreamHandler(logger, repo, cacheInstance)
	listUpstreamHandler := handlers.NewListUpstreamHandler(logger, repo, cacheInstance)
	getUpstreamHandler := handlers.NewGetUpstreamHandler(logger, repo, cacheInstance, upstreamFinder)
	updateUpstreamHandler := handlers.NewUpdateUpstreamHandler(logger, repo, cacheInstance)
	deleteUpstreamHandler := handlers.NewDeleteUpstreamHandler(logger, repo, cacheInstance)

	createServiceHandler := handlers.NewCreateServiceHandler(logger, repo, cacheInstance)
	listServicesHandler := handlers.NewListServicesHandler(logger, repo)
	getServiceHandler := handlers.NewGetServiceHandler(logger, serviceRepository, cacheInstance)
	updateServiceHandler := handlers.NewUpdateServiceHandler(logger, repo, cacheInstance)
	deleteServiceHandler := handlers.NewDeleteServiceHandler(logger, repo, cacheInstance)

	createRuleHandler := handlers.NewCreateRuleHandler(logger, repo, validateRule)
	listRulesHandler := handlers.NewListRulesHandler(logger, repo, cacheInstance)
	updateRuleHandler := handlers.NewUpdateRuleHandler(logger, repo, cacheInstance, validateRule, invalidateCachePublisher)
	deleteRuleHandler := handlers.NewDeleteRuleHandler(logger, repo, cacheInstance, invalidateCachePublisher)

	createApiKeyHandler := handlers.NewCreateAPIKeyHandler(logger, repo, cacheInstance)
	listApiKeysHandler := handlers.NewListAPIKeysHandler(logger, repo)
	getApiKeyHandler := handlers.NewGetAPIKeyHandler(logger, cacheInstance)
	deleteApiKeyHandler := handlers.NewDeleteAPIKeyHandler(logger, cacheInstance)

	// Handler Transport
	handlerTransport := handlers.HandlerTransport{
		// Proxy
		ForwardedHandler: forwardedHandler,
		// Gateway
		CreateGatewayHandler: createGatewayHandler,
		ListGatewayHandler:   listGatewayHandler,
		GetGatewayHandler:    getGatewayHandler,
		UpdateGatewayHandler: updateGatewayHandler,
		DeleteGatewayHandler: deleteGatewayHandler,
		// Upstream
		CreateUpstreamHandler: createUpstreamHandler,
		ListUpstreamHandler:   listUpstreamHandler,
		GetUpstreamHandler:    getUpstreamHandler,
		UpdateUpstreamHandler: updateUpstreamHandler,
		DeleteUpstreamHandler: deleteUpstreamHandler,
		// Service
		CreateServiceHandler: createServiceHandler,
		ListServicesHandler:  listServicesHandler,
		GetServiceHandler:    getServiceHandler,
		UpdateServiceHandler: updateServiceHandler,
		DeleteServiceHandler: deleteServiceHandler,
		// Rule
		CreateRuleHandler: createRuleHandler,
		ListRulesHandler:  listRulesHandler,
		UpdateRuleHandler: updateRuleHandler,
		DeleteRuleHandler: deleteRuleHandler,
		// APIKey
		CreateAPIKeyHandler: createApiKeyHandler,
		ListAPIKeysHandler:  listApiKeysHandler,
		GetAPIKeyHandler:    getApiKeyHandler,
		DeleteAPIKeyHandler: deleteApiKeyHandler,
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
