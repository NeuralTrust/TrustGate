package config

import (
	"errors"
	"fmt"
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
	Plugins   PluginsConfig   `mapstructure:"plugins"`
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

type PluginsConfig struct {
	IgnoreErrors bool `mapstructure:"ignore_errors"`
}

var globalConfig Config
var providerConfig ProvidersConfig

func Load(configPath string) error {
	if err := loadConfigFile(configPath, "config", &globalConfig); err != nil {
		return fmt.Errorf("⚠️ Warning: Could not load main config file: %v", err)
	}

	setDefaultValues()

	if err := loadConfigFile(configPath, "providers", &providerConfig); err != nil {
		return fmt.Errorf("⚠️ Warning: Could not load providers config file: %v", err)
	}

	globalConfig.Providers = providerConfig

	return nil
}

func loadConfigFile(configPath, fileName string, out interface{}) error {
	viper.SetConfigName(fileName)
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configPath)
	viper.AddConfigPath("./config")
	viper.AddConfigPath(".")

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if errors.As(err, &configFileNotFoundError) {
			return fmt.Errorf("config file %s.yaml not found, using only environment variables", fileName)
		}
		return fmt.Errorf("error reading config file %s.yaml: %w", fileName, err)
	}

	if err := viper.Unmarshal(out); err != nil {
		return fmt.Errorf("failed to unmarshal %s config: %w", fileName, err)
	}

	return nil
}

func setDefaultValues() {
	if globalConfig.Database.SSLMode == "" {
		globalConfig.Database.SSLMode = "disable"
	}
}

func GetConfig() *Config {
	return &globalConfig
}
