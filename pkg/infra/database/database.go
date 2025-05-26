package database

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/domain/forwarding_rule"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func GetRegisteredModels() []interface{} {
	return []interface{}{
		&gateway.Gateway{},
		&forwarding_rule.ForwardingRule{},
		&apikey.APIKey{},
		&service.Service{},
		&upstream.Upstream{},
	}
}

// DB represents the database connection
type DB struct {
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
func NewDB(cfg *Config, models []interface{}) (*DB, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode)

	gormDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := gormDB.AutoMigrate(models...); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate schema: %w", err)
	}

	return &DB{DB: gormDB}, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
