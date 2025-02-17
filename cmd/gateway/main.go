package main

import (
	"bufio"
	"log"
	"os"
	"sync"

	"github.com/NeuralTrust/TrustGate/internal/logger"
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

// Get server type safely
func getServerType() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	return "proxy" // default to proxy server
}

func initializeServer(cfg *config.Config, cache *cache.Cache, repo *database.Repository) server.Server {
	serverType := getServerType()

	switch serverType {
	case "admin":
		return server.NewAdminServer(cfg, cache, repo)
	default:
		return server.NewProxyServer(cfg, cache, repo, false)
	}
}

func main() {

	// Load configuration
	if err := config.Load(); err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	cfg := config.NewConfig()

	// Get server type once at the start
	serverType := getServerType()

	l := logger.NewLogger(serverType, cfg.LoggerConfig.Level)

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
		log.Fatalf("failed to initialize database: %v", err)
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
		log.Fatalf("Failed to initialize cache: %v", err)
	}

	// Initialize repository
	repo := database.NewRepository(db.DB, cacheInstance)

	// Create and initialize the server
	srv := initializeServer(cfg, cacheInstance, repo)

	if err := srv.Run(); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
