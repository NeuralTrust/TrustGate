package database

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// DB represents the database connection
type DB struct {
	logger *logrus.Logger
	*gorm.DB
}

// Config holds database configuration
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// NewDB creates a new database connection
func NewDB(logger *logrus.Logger, cfg *Config) (*DB, error) {
	logger.WithFields(logrus.Fields{
		"host":    cfg.Host,
		"port":    cfg.Port,
		"db":      cfg.DBName,
		"user":    cfg.User,
		"sslmode": cfg.SSLMode,
		"timeout": "30s",
	}).Info("connecting to database")

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode)

	gormDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := gormDB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql DB: %w", err)
	}
	// Defaults tuned for moderate concurrency; adjust as needed
	sqlDB.SetMaxOpenConns(300)
	sqlDB.SetMaxIdleConns(150)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)
	sqlDB.SetConnMaxIdleTime(60 * time.Second)
	logger.WithFields(logrus.Fields{
		"max_open_conns":     300,
		"max_idle_conns":     150,
		"conn_max_lifetime":  "5m",
		"conn_max_idle_time": "60s",
	}).Info("configured database connection pool")

	// Verify connectivity with a timeout (30s)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("database ping failed: %w", err)
	}

	db := &DB{logger: logger, DB: gormDB}
	migrationsManager := NewMigrationsManager(db.DB)

	// Apply migrations with a timeout (30s)
	logger.WithField("timeout", "30s").Info("applying database migrations")
	migCtx, migCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer migCancel()
	migErrCh := make(chan error, 1)
	go func() {
		migErrCh <- migrationsManager.ApplyPending()
	}()
	select {
	case err := <-migErrCh:
		if err != nil {
			logger.WithError(err).Error("failed to apply database migrations")
			return nil, fmt.Errorf("failed to apply database migrations: %w", err)
		}
		fmt.Println("✓ database migrations successfully applied")
	case <-migCtx.Done():
		logger.WithError(migCtx.Err()).Error("database migrations timed out")
		return nil, fmt.Errorf("database migrations timed out: %w", migCtx.Err())
	}

	return db, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
