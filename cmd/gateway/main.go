package main

import (
	"bufio"
	"fmt"
	"github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/database"
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
	manager := plugins.GetManager()

	// Initialize repository
	repo := database.NewRepository(db.DB, logger, cacheInstance)
	upstreamRepository := repository.NewUpstreamRepository(db.DB)

	// service
	upstreamFinder := upstream.NewFinder(upstreamRepository, cacheInstance)

	// Create and initialize the server
	adminServerDI := server.AdminServerDI{
		Config:         cfg,
		Logger:         logger,
		Cache:          cacheInstance,
		Repo:           repo,
		Manager:        manager,
		UpstreamFinder: upstreamFinder,
	}

	proxyServerDI := server.ProxyServerDI{
		Config:         cfg,
		Logger:         logger,
		Cache:          cacheInstance,
		Repo:           repo,
		Manager:        manager,
		UpstreamFinder: upstreamFinder,
		SkipAuthCheck:  false,
	}

	srv := initializeServer(proxyServerDI, adminServerDI)

	if err := srv.Run(); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}
