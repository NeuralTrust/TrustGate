package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	"github.com/NeuralTrust/TrustGate/pkg/app/rule"
	"github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	handlers "github.com/NeuralTrust/TrustGate/pkg/handlers/http"
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

// syncWriter wraps a buffered writer and ensures each write is flushed
type syncWriter struct {
	writer *bufio.Writer
	file   *os.File
	mu     sync.Mutex
}

// Write implements io.Writer
func (w *syncWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Write the data
	n, err = w.writer.Write(p)
	if err != nil {
		return n, err
	}

	// Ensure the write is flushed to disk
	if err = w.writer.Flush(); err != nil {
		return n, err
	}

	// Sync to disk to ensure durability
	return n, w.file.Sync()
}

// ConsoleHook is a logrus hook that writes to stdout
type ConsoleHook struct{}

// Fire implements logrus.Hook
func (h *ConsoleHook) Fire(entry *logrus.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}
	fmt.Print(line)
	return nil
}

// Levels implements logrus.Hook
func (h *ConsoleHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Get server type safely
func getServerType() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return "proxy" // default to proxy server
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

	// Create a buffered writer with a larger buffer size
	writer := bufio.NewWriterSize(file, 32*1024) // 32KB buffer
	defer writer.Flush()

	// Create a synchronized writer that ensures atomic writes
	syncedWriter := &syncWriter{
		writer: writer,
		file:   file,
	}

	// Set the logger output to the file
	logger.SetOutput(syncedWriter)

	// In debug mode, add a hook for stdout
	if os.Getenv("LOG_LEVEL") == "debug" {
		logger.AddHook(&ConsoleHook{})
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

	// service
	upstreamFinder := upstream.NewFinder(upstreamRepository, cacheInstance)
	updateGatewayCache := gateway.NewUpdateGatewayCache(cacheInstance)
	getGatewayCache := gateway.NewGetGatewayCache(cacheInstance)
	invalidateCachePublisher := infraCache.NewInvalidationPublisher(cacheInstance)
	invalidateGatewayCache := gateway.NewInvalidateGatewayCache(cacheInstance, invalidateCachePublisher)
	validatePlugin := plugin.NewValidatePlugin()
	validateRule := rule.NewValidateRule(validatePlugin)

	//middleware
	middlewareTransport := middleware.Transport{
		AuthMiddleware:    middleware.NewAuthMiddleware(logger, repo, false),
		GatewayMiddleware: middleware.NewGatewayMiddleware(logger, cacheInstance, repo, cfg.Server.BaseDomain),
		MetricsMiddleware: middleware.NewMetricsMiddleware(logger),
	}

	//handler
	forwardedHandler := handlers.NewForwardedHandler(
		logger,
		repo,
		cacheInstance,
		upstreamFinder,
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
	getServiceHandler := handlers.NewGetServiceHandler(logger, repo, cacheInstance)
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
