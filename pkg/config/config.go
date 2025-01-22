package config

import (
	"fmt"
	"os"

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
	Server    ServerConfig    `yaml:"server"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Database  DatabaseConfig  `yaml:"database"`
	Redis     RedisConfig     `yaml:"redis"`
	Providers ProvidersConfig `yaml:"providers"`
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

var (
	// Global configuration
	globalConfig Config
)

// Load loads the configuration from config files
func Load() error {
	// Read config file directly from the config directory
	data, err := os.ReadFile("./config/config.yaml")
	if err != nil {
		// Try to get current working directory for debugging
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to read config file and get working directory: %w", err)
		}
		fmt.Printf("Working directory: %s\n", cwd)
		return fmt.Errorf("failed to read config file: %w", err)
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
	return nil
}

// GetConfig returns the global configuration
func GetConfig() *Config {
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
