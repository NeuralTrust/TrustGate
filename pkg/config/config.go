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
	Plugins   PluginsConfig   `mapstructure:"plugins"`
	WebSocket WebSocketConfig `mapstructure:"websocket"`
	TLS       TLSConfig       `mapstructure:"tls"`
}

type ServerConfig struct {
	AdminPort   int    `mapstructure:"admin_port"`
	ProxyPort   int    `mapstructure:"proxy_port"`
	MetricsPort int    `mapstructure:"metrics_port"`
	Type        string `mapstructure:"type"`
	Port        int    `mapstructure:"port"`
	Host        string `mapstructure:"host"`
	SecretKey   string `mapstructure:"secret_key"`
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
	TLS      bool   `mapstructure:"tls"`
}

type PluginsConfig struct {
	IgnoreErrors bool `mapstructure:"ignore_errors"`
}

type WebSocketConfig struct {
	MaxConnections int    `mapstructure:"max_connections"`
	PingPeriod     string `mapstructure:"ping_period"`
	PongWait       string `mapstructure:"pong_wait"`
}

type TLSConfig struct {
	Disabled            bool       `mapstructure:"disabled"`
	EnableMTLS          bool       `mapstructure:"enable_mtls"`
	DisableSystemCAPool bool       `mapstructure:"disable_system_ca_pool"`
	CACert              string     `mapstructure:"ca_cert"`
	Keys                TLSKeyPair `mapstructure:"keys"`
	CipherSuites        []uint16   `mapstructure:"cipher_suites"`
	CurvePreferences    []uint16   `mapstructure:"curve_preferences"`
	MinVersion          string     `mapstructure:"min_version"`
	MaxVersion          string     `mapstructure:"max_version"`
}

type TLSKeyPair struct {
	PublicKey  string `mapstructure:"public_key"`
	PrivateKey string `mapstructure:"private_key"`
}

var globalConfig Config

func Load(configPath string) error {
	if err := loadConfigFile(configPath, "config", &globalConfig); err != nil {
		return fmt.Errorf("⚠️ Warning: Could not load main config file: %v", err)
	}
	setDefaultValues()
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
