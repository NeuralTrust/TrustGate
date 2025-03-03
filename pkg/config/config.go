package config

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/spf13/viper"
)

type MetricsConfig struct {
	Enabled           bool `mapstructure:"enabled"`
	RetentionDays     int  `mapstructure:"retention_days"`
	EnableLatency     bool `mapstructure:"enable_latency"`
	EnableUpstream    bool `mapstructure:"enable_upstream"`
	EnableConnections bool `mapstructure:"enable_connections"`
	EnablePerRoute    bool `mapstructure:"enable_per_route"`
}

type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Metrics   MetricsConfig   `mapstructure:"metrics"`
	Database  DatabaseConfig  `mapstructure:"database"`
	Redis     RedisConfig     `mapstructure:"redis"`
	Providers ProvidersConfig `mapstructure:"providers"`
	AWS       AWSConfig       `mapstructure:"aws"`
	Azure     AzureConfig     `mapstructure:"azure"`
	OpenAi    OpenAiConfig    `mapstructure:"openai"`
}

type ServerConfig struct {
	AdminPort   int    `mapstructure:"admin_port"`
	ProxyPort   int    `mapstructure:"proxy_port"`
	MetricsPort int    `mapstructure:"metrics_port"`
	Type        string `mapstructure:"type"`
	Port        int    `mapstructure:"port"`
	BaseDomain  string `mapstructure:"base_domain"`
	Host        string `mapstructure:"host"`
}

type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"name"`
	SSLMode  string `mapstructure:"sslmode"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type AWSConfig struct {
	Region    string `mapstructure:"region"`
	AccessKey string `mapstructure:"access_key"`
	SecretKey string `mapstructure:"secret_key"`
}

type AzureConfig struct {
	ApiKey string `mapstructure:"api_key"`
}

type OpenAiConfig struct {
	ApiKey string `mapstructure:"api_key"`
}

var globalConfig Config

// Load reads configuration from file and environment variables
func Load() error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./config")
	viper.AddConfigPath(".")

	// Support environment variables
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Load configuration file
	if err := viper.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			log.Println("Warning: Config file not found, using only environment variables")
		}
	}

	if err := viper.Unmarshal(&globalConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if globalConfig.Database.SSLMode == "" {
		globalConfig.Database.SSLMode = "disable"
	}

	return nil
}

// GetConfig returns the global configuration
func GetConfig() *Config {
	return &globalConfig
}
