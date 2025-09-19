package database

import (
	"fmt"

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
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode)

	gormDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	db := &DB{logger: logger, DB: gormDB}
	migrationsManager := NewMigrationsManager(db.DB)

	if err := migrationsManager.ApplyPending(); err != nil {
		logger.WithError(err).Error("failed to apply database migrations")
	} else {
		fmt.Println("✓ database migrations successfully applied")
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
