package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

// MetricsConfig holds configuration for metrics collection
type MetricsConfig struct {
	Enabled           bool `yaml:"enabled"`
	RetentionDays     int  `yaml:"retention_days"`
	EnableLatency     bool `yaml:"enable_latency"`
	EnableUpstream    bool `yaml:"enable_upstream"`
	EnableConnections bool `yaml:"enable_connections"`
	EnablePerRoute    bool `yaml:"enable_per_route"`
}

// Config represents the main configuration structure
type Config struct {
	Server       ServerConfig    `yaml:"server"`
	Metrics      MetricsConfig   `yaml:"metrics"`
	Database     DatabaseConfig  `yaml:"database"`
	Redis        RedisConfig     `yaml:"redis"`
	Providers    ProvidersConfig `yaml:"providers"`
	LoggerConfig LoggerConfig    `yaml:"logger"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	AdminPort   int    `yaml:"admin_port"`
	ProxyPort   int    `yaml:"proxy_port"`
	MetricsPort int    `yaml:"metrics_port"`
	Type        string `yaml:"type"`
	Port        int    `yaml:"port"`
	BaseDomain  string `yaml:"base_domain"`
	Host        string `yaml:"host"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DBName   string `yaml:"dbname"`
	SSLMode  string `yaml:"sslmode"`
}

type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type LoggerConfig struct {
	Level string `yaml:"level"`
}

var (
	// Global configuration
	globalConfig Config
)

// Load loads the configuration from config files
func Load() error {
	// Get config path from environment variable or use default
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "./config/config.yaml"
	}

	// Clean and validate the path
	configPath = filepath.Clean(configPath)

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		// Try to get current working directory for debugging
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to read config file and get working directory: %w", err)
		}
		fmt.Printf("Working directory: %s\n", cwd)
		return fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	// Unmarshal YAML directly
	if err := yaml.Unmarshal(data, &globalConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Load provider config
	providerConfig, err := LoadProviderConfig()
	if err != nil {
		return fmt.Errorf("failed to load provider config: %w", err)
	}
	globalConfig.Providers = *providerConfig

	// Override with environment variables if present
	loadEnvOverrides()

	return nil
}

// loadEnvOverrides overrides config values with environment variables if present
func loadEnvOverrides() {
	// Database overrides
	if host := os.Getenv("DB_HOST"); host != "" {
		globalConfig.Database.Host = host
	}
	if port := os.Getenv("DB_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			globalConfig.Database.Port = p
		}
	}
	if user := os.Getenv("DB_USER"); user != "" {
		globalConfig.Database.User = user
	}
	if pass := os.Getenv("DB_PASSWORD"); pass != "" {
		globalConfig.Database.Password = pass
	}
	if name := os.Getenv("DB_NAME"); name != "" {
		globalConfig.Database.DBName = name
	}

	// Redis overrides
	if host := os.Getenv("REDIS_HOST"); host != "" {
		globalConfig.Redis.Host = host
	}
	if port := os.Getenv("REDIS_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			globalConfig.Redis.Port = p
		}
	}
	if pass := os.Getenv("REDIS_PASSWORD"); pass != "" {
		globalConfig.Redis.Password = pass
	}

	// Server overrides
	if port := os.Getenv("ADMIN_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			globalConfig.Server.AdminPort = p
		}
	}
	if port := os.Getenv("PROXY_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			globalConfig.Server.ProxyPort = p
		}
	}
	if port := os.Getenv("METRICS_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			globalConfig.Server.MetricsPort = p
		}
	}
	if host := os.Getenv("BASE_DOMAIN"); host != "" {
		globalConfig.Server.BaseDomain = host
	}

	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		globalConfig.LoggerConfig.Level = logLevel
	}
}

func NewConfig() *Config {
	return &globalConfig
}

// GetDatabaseConfig returns the database configuration
func GetDatabaseConfig() DatabaseConfig {
	return globalConfig.Database
}

// GetServerConfig returns the server configuration
func GetServerConfig() ServerConfig {
	return globalConfig.Server
}

// GetRedisConfig returns the redis configuration
func GetRedisConfig() RedisConfig {
	return globalConfig.Redis
}
