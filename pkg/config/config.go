// Package config loads configuration from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/common/errors"
)

const (
	defaultAppEnv = "dev"

	defaultServerAdminPort    = 8080
	defaultServerProxyPort    = 8081
	defaultServerReadTimeout  = 60 * time.Second
	defaultServerWriteTimeout = 60 * time.Second
	defaultServerIdleTimeout  = 120 * time.Second

	defaultDBHost                    = "localhost"
	defaultDBPort                    = 5432
	defaultDBUser                    = "postgres"
	defaultDBPassword                = "postgres" // #nosec G101 -- dev default, override via env
	defaultDBName                    = "agentgateway"
	defaultDBSSLMode                 = "disable"
	defaultDBMinConns          int32 = 1
	defaultDBMaxConns          int32 = 10
	defaultDBMaxConnLifetime         = time.Hour
	defaultDBMaxConnIdleTime         = 30 * time.Minute
	defaultDBHealthCheckPeriod       = time.Minute
	defaultDBConnectTimeout          = 5 * time.Second

	defaultRedisHost = "localhost"
	defaultRedisPort = 6379
	defaultRedisDB   = 0
	defaultRedisTLS  = false

	defaultCacheLocalTTL = 5 * time.Minute

	defaultKafkaBrokers = "localhost:9092"

	defaultTelemetryEnabled          = true
	defaultTelemetryKafkaTopic       = "agentgateway.requests"
	defaultTelemetryTrustLensEnabled = false
	defaultTelemetryTrustLensURL     = ""

	defaultMetricsEnabled       = true
	defaultMetricsQueueSize     = 1000
	defaultMetricsWorkerCount   = 1
	defaultMetricsFlushInterval = 5 * time.Second

	defaultUpstreamTimeout          = 60 * time.Second
	defaultUpstreamErrorPassthrough = true

	defaultProviderRequestTimeout = 60 * time.Second
	defaultProviderMaxRetries     = 2

	defaultCORSAllowOrigins     = "*"
	defaultCORSAllowMethods     = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
	defaultCORSAllowHeaders     = "Content-Type,Authorization,X-Request-Id"
	defaultCORSExposeHeaders    = "X-Request-Id"
	defaultCORSAllowCredentials = false
	defaultCORSMaxAge           = "600"

	defaultLogLevel  = "INFO"
	defaultLogFormat = "json"
)

type Config struct {
	AppEnv    string
	Server    ServerConfig
	Database  DatabaseConfig
	Redis     RedisConfig
	Cache     CacheConfig
	Kafka     KafkaConfig
	Telemetry TelemetryConfig
	Metrics   MetricsConfig
	Upstream  UpstreamConfig
	Provider  ProviderConfig
	Catalog   CatalogConfig
	CORS      CORSConfig
	Logger    LoggerConfig
}

type ServerConfig struct {
	AdminPort    int
	ProxyPort    int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	// SecretKey signs and verifies admin-plane JWTs. Empty disables admin auth
	// token acceptance (every token is rejected).
	SecretKey string
}

type DatabaseConfig struct {
	Host              string
	Port              int
	User              string
	Password          string // #nosec G117 -- config struct field, not a hardcoded credential
	Name              string
	SSLMode           string
	SSLRootCert       string
	MinConns          int32
	MaxConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
	ConnectTimeout    time.Duration
}

type RedisConfig struct {
	Host              string
	Port              int
	Password          string
	DB                int
	TLSEnabled        bool
	TLSInsecureVerify bool
}

// CacheConfig drives the in-process TTL cache used by app-layer
// finders. RUN-291 (B.1) will add a parallel Redis-backed layer; the
// finder contract will not change.
type CacheConfig struct {
	LocalTTL time.Duration
}

type KafkaConfig struct {
	Brokers []string
}

type TelemetryConfig struct {
	Enabled          bool
	KafkaTopic       string
	TrustLensEnabled bool
	TrustLensURL     string
}

type MetricsConfig struct {
	Enabled       bool
	QueueSize     int
	WorkerCount   int
	FlushInterval time.Duration
}

type UpstreamConfig struct {
	Timeout          time.Duration
	ErrorPassthrough bool
}

type ProviderConfig struct {
	RequestTimeout time.Duration
	MaxRetries     int
}

type CatalogConfig struct {
	OpenRouterAPIKey  string
	OpenRouterBaseURL string
}

// CORSConfig drives the CORSMiddleware applied by both admin and proxy.
// Lists are comma-separated in env. Use "*" in AllowOrigins to allow any.
type CORSConfig struct {
	AllowOrigins     []string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           string
}

type LoggerConfig struct {
	Level  slog.Level
	Format string
}

func LoadConfig() (*Config, error) {
	cfg := &Config{
		AppEnv:    getEnv("APP_ENV", defaultAppEnv),
		Server:    getServerConfig(),
		Database:  getDatabaseConfig(),
		Redis:     getRedisConfig(),
		Cache:     getCacheConfig(),
		Kafka:     getKafkaConfig(),
		Telemetry: getTelemetryConfig(),
		Metrics:   getMetricsConfig(),
		Upstream:  getUpstreamConfig(),
		Provider:  getProviderConfig(),
		Catalog:   getCatalogConfig(),
		CORS:      getCORSConfig(),
		Logger:    getLoggerConfig(),
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func getServerConfig() ServerConfig {
	return ServerConfig{
		AdminPort:    getEnvInt("SERVER_ADMIN_PORT", defaultServerAdminPort),
		ProxyPort:    getEnvInt("SERVER_PROXY_PORT", defaultServerProxyPort),
		ReadTimeout:  getEnvDuration("SERVER_READ_TIMEOUT", defaultServerReadTimeout),
		WriteTimeout: getEnvDuration("SERVER_WRITE_TIMEOUT", defaultServerWriteTimeout),
		IdleTimeout:  getEnvDuration("SERVER_IDLE_TIMEOUT", defaultServerIdleTimeout),
		SecretKey:    getEnv("SERVER_SECRET_KEY", ""),
	}
}

func getDatabaseConfig() DatabaseConfig {
	return DatabaseConfig{
		Host:              getEnv("DB_HOST", defaultDBHost),
		Port:              getEnvInt("DB_PORT", defaultDBPort),
		User:              getEnv("DB_USER", defaultDBUser),
		Password:          getEnv("DB_PASSWORD", defaultDBPassword),
		Name:              getEnv("DB_NAME", defaultDBName),
		SSLMode:           getEnv("DB_SSL_MODE", defaultDBSSLMode),
		SSLRootCert:       getEnv("DB_SSL_ROOT_CERT", ""),
		MinConns:          getEnvInt32("DB_MIN_CONNS", defaultDBMinConns),
		MaxConns:          getEnvInt32("DB_MAX_CONNS", defaultDBMaxConns),
		MaxConnLifetime:   getEnvDuration("DB_MAX_CONN_LIFETIME", defaultDBMaxConnLifetime),
		MaxConnIdleTime:   getEnvDuration("DB_MAX_CONN_IDLE_TIME", defaultDBMaxConnIdleTime),
		HealthCheckPeriod: getEnvDuration("DB_HEALTH_CHECK_PERIOD", defaultDBHealthCheckPeriod),
		ConnectTimeout:    getEnvDuration("DB_CONNECT_TIMEOUT", defaultDBConnectTimeout),
	}
}

func getRedisConfig() RedisConfig {
	return RedisConfig{
		Host:              getEnv("REDIS_HOST", defaultRedisHost),
		Port:              getEnvInt("REDIS_PORT", defaultRedisPort),
		Password:          getEnv("REDIS_PASSWORD", ""),
		DB:                getEnvInt("REDIS_DB", defaultRedisDB),
		TLSEnabled:        getEnvBool("REDIS_TLS_ENABLED", defaultRedisTLS),
		TLSInsecureVerify: getEnvBool("REDIS_TLS_INSECURE_VERIFY", false),
	}
}

func getCacheConfig() CacheConfig {
	return CacheConfig{
		LocalTTL: getEnvDuration("CACHE_LOCAL_TTL", defaultCacheLocalTTL),
	}
}

func getKafkaConfig() KafkaConfig {
	return KafkaConfig{Brokers: splitCSV(getEnv("KAFKA_BROKERS", defaultKafkaBrokers))}
}

func getTelemetryConfig() TelemetryConfig {
	return TelemetryConfig{
		Enabled:          getEnvBool("TELEMETRY_ENABLED", defaultTelemetryEnabled),
		KafkaTopic:       getEnv("TELEMETRY_KAFKA_TOPIC", defaultTelemetryKafkaTopic),
		TrustLensEnabled: getEnvBool("TELEMETRY_TRUSTLENS_ENABLED", defaultTelemetryTrustLensEnabled),
		TrustLensURL:     getEnv("TELEMETRY_TRUSTLENS_URL", defaultTelemetryTrustLensURL),
	}
}

func getMetricsConfig() MetricsConfig {
	return MetricsConfig{
		Enabled:       getEnvBool("METRICS_ENABLED", defaultMetricsEnabled),
		QueueSize:     getEnvInt("METRICS_QUEUE_SIZE", defaultMetricsQueueSize),
		WorkerCount:   getEnvInt("METRICS_WORKER_COUNT", defaultMetricsWorkerCount),
		FlushInterval: getEnvDuration("METRICS_FLUSH_INTERVAL", defaultMetricsFlushInterval),
	}
}

func getUpstreamConfig() UpstreamConfig {
	return UpstreamConfig{
		Timeout:          getEnvDuration("UPSTREAM_TIMEOUT", defaultUpstreamTimeout),
		ErrorPassthrough: getEnvBool("UPSTREAM_ERROR_PASSTHROUGH", defaultUpstreamErrorPassthrough),
	}
}

func getProviderConfig() ProviderConfig {
	return ProviderConfig{
		RequestTimeout: getEnvDuration("PROVIDER_REQUEST_TIMEOUT", defaultProviderRequestTimeout),
		MaxRetries:     getEnvInt("PROVIDER_MAX_RETRIES", defaultProviderMaxRetries),
	}
}

func getCatalogConfig() CatalogConfig {
	return CatalogConfig{
		OpenRouterAPIKey:  getEnv("OPENROUTER_API_KEY", ""),
		OpenRouterBaseURL: getEnv("OPENROUTER_BASE_URL", ""),
	}
}

// splitCSV trims whitespace and drops empty tokens so " a, , b " -> ["a","b"].
func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func getCORSConfig() CORSConfig {
	return CORSConfig{
		AllowOrigins:     splitCSV(getEnv("CORS_ALLOW_ORIGINS", defaultCORSAllowOrigins)),
		AllowMethods:     splitCSV(getEnv("CORS_ALLOW_METHODS", defaultCORSAllowMethods)),
		AllowHeaders:     splitCSV(getEnv("CORS_ALLOW_HEADERS", defaultCORSAllowHeaders)),
		ExposeHeaders:    splitCSV(getEnv("CORS_EXPOSE_HEADERS", defaultCORSExposeHeaders)),
		AllowCredentials: getEnvBool("CORS_ALLOW_CREDENTIALS", defaultCORSAllowCredentials),
		MaxAge:           getEnv("CORS_MAX_AGE", defaultCORSMaxAge),
	}
}

func getLoggerConfig() LoggerConfig {
	return LoggerConfig{
		Level:  getLogLevel(),
		Format: getEnv("LOG_FORMAT", defaultLogFormat),
	}
}

func (c *Config) Validate() error {
	if c.Database.Host == "" {
		return fmt.Errorf("%w: DB_HOST is required", errors.ErrInvalidConfig)
	}
	if c.Database.User == "" {
		return fmt.Errorf("%w: DB_USER is required", errors.ErrInvalidConfig)
	}
	if c.Database.Name == "" {
		return fmt.Errorf("%w: DB_NAME is required", errors.ErrInvalidConfig)
	}
	if c.Redis.Host == "" {
		return fmt.Errorf("%w: REDIS_HOST is required", errors.ErrInvalidConfig)
	}
	if len(c.Kafka.Brokers) == 0 {
		return fmt.Errorf("%w: KAFKA_BROKERS must contain at least one broker", errors.ErrInvalidConfig)
	}
	if c.Telemetry.Enabled && c.Telemetry.KafkaTopic == "" {
		return fmt.Errorf("%w: TELEMETRY_KAFKA_TOPIC is required when telemetry is enabled", errors.ErrInvalidConfig)
	}
	if c.Telemetry.TrustLensEnabled && c.Telemetry.TrustLensURL == "" {
		return fmt.Errorf("%w: TELEMETRY_TRUSTLENS_URL is required when TrustLens telemetry is enabled", errors.ErrInvalidConfig)
	}
	if c.Metrics.Enabled && c.Metrics.QueueSize <= 0 {
		return fmt.Errorf("%w: METRICS_QUEUE_SIZE must be greater than zero", errors.ErrInvalidConfig)
	}
	if c.Metrics.Enabled && c.Metrics.WorkerCount <= 0 {
		return fmt.Errorf("%w: METRICS_WORKER_COUNT must be greater than zero", errors.ErrInvalidConfig)
	}
	if c.Provider.MaxRetries < 0 {
		return fmt.Errorf("%w: PROVIDER_MAX_RETRIES must be zero or greater", errors.ErrInvalidConfig)
	}
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		slog.Warn("invalid integer environment variable, falling back to default",
			slog.String("key", key), slog.String("value", sanitizeLogValue(value)))
		return defaultValue
	}
	return parsed
}

func getEnvInt32(key string, defaultValue int32) int32 {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsed < 0 {
		slog.Warn("invalid int32 environment variable, falling back to default",
			slog.String("key", key), slog.String("value", sanitizeLogValue(value)))
		return defaultValue
	}
	return int32(parsed)
}

func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		slog.Warn("invalid bool environment variable, falling back to default",
			slog.String("key", key), slog.String("value", sanitizeLogValue(value)))
		return defaultValue
	}
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		slog.Warn("invalid duration environment variable, falling back to default",
			slog.String("key", key), slog.String("value", sanitizeLogValue(value)))
		return defaultValue
	}
	return parsed
}

func getLogLevel() slog.Level {
	levelStr := getEnv("LOG_LEVEL", defaultLogLevel)
	var level slog.Level
	if err := level.UnmarshalText([]byte(levelStr)); err != nil {
		slog.Warn("invalid LOG_LEVEL, falling back to INFO",
			slog.String("value", sanitizeLogValue(levelStr)))
		return slog.LevelInfo
	}
	return level
}

// sanitizeLogValue strips control characters so user-supplied env values
// cannot inject newlines / fake fields into structured logs.
func sanitizeLogValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
}
