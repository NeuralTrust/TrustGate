// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package config loads configuration from environment variables.
package config

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

const (
	defaultAppEnv = "dev"

	defaultServerAdminPort    = 8080
	defaultServerProxyPort    = 8081
	defaultServerMCPPort      = 8082
	defaultServerReadTimeout  = 60 * time.Second
	defaultServerWriteTimeout = 60 * time.Second
	defaultServerIdleTimeout  = 120 * time.Second
	defaultGatewayBaseDomain  = "llm.neuraltrust.ai"
	defaultMCPBaseDomain      = "mcp.neuraltrust.ai"

	GatewayDiscoveryModeHeader    = "header"
	GatewayDiscoveryModeSubdomain = "subdomain"

	defaultDBHost                    = "localhost"
	defaultDBPort                    = 5432
	defaultDBUser                    = "trustgate"
	defaultDBPassword                = "postgres" // #nosec G101 -- dev default, override via env
	defaultDBName                    = "trustgate"
	defaultDBSSLMode                 = "disable"
	defaultDBMinConns          int32 = 1
	defaultDBMaxConns          int32 = 10
	defaultDBMaxConnLifetime         = time.Hour
	defaultDBMaxConnIdleTime         = 30 * time.Minute
	defaultDBHealthCheckPeriod       = time.Minute
	defaultDBConnectTimeout          = 5 * time.Second

	postgresLoginDefault = "default"
	postgresLoginAWS     = "aws"

	redisLoginDefault = "default"
	redisLoginAWS     = "aws"

	defaultRedisHost = "localhost"
	defaultRedisPort = 6379
	defaultRedisDB   = 3
	defaultRedisTLS  = false

	defaultCacheLocalTTL = 5 * time.Minute

	defaultSessionStoreEnabled = true
	defaultSessionStoreTTL     = time.Hour

	defaultKafkaBrokers = "localhost:9092"

	defaultTelemetryEnabled             = true
	defaultTelemetryKafkaTopic          = "trustgate.requests"
	defaultTelemetryEnableRequestTraces = true
	defaultTelemetryEnablePluginTraces  = true
	defaultTelemetryExportersFile       = "config/telemetry.yaml"

	defaultMetricsEnabled       = true
	defaultMetricsQueueSize     = 1000
	defaultMetricsWorkerCount   = 1
	defaultMetricsFlushInterval = 5 * time.Second

	defaultPlaygroundTraceStoreEnabled = true
	defaultPlaygroundTraceStoreTTL     = 10 * time.Minute

	defaultUpstreamTimeout          = 60 * time.Second
	defaultUpstreamErrorPassthrough = true

	defaultProviderRequestTimeout = 60 * time.Second
	defaultProviderMaxRetries     = 2

	defaultCORSAllowOrigins     = "*"
	defaultCORSAllowMethods     = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
	defaultCORSAllowHeaders     = "Content-Type,Authorization,X-AG-Trace-Id"
	defaultCORSExposeHeaders    = "X-AG-Trace-Id"
	defaultCORSAllowCredentials = false
	defaultCORSMaxAge           = "600"

	defaultLogLevel       = "INFO"
	defaultLogFormat      = "json"
	defaultLogFileEnabled = false

	defaultSemanticCacheVectorStore = "redis"

	defaultTrustGuardTimeout = 15 * time.Second

	defaultOpenAIModerationTimeout = 15 * time.Second

	defaultConfigSyncDataPlaneEnabled  = false
	defaultConfigSyncLKGPath           = "/var/lib/trustgate/snapshot.lkg"
	defaultConfigSyncPollInterval      = 5 * time.Minute
	defaultConfigSyncRecompileDebounce = 2 * time.Second
	defaultConfigSyncRecompileBackstop = 5 * time.Minute

	defaultRateLimitEnabled    = false
	defaultEntitlementsMutable = false

	defaultConfigSyncGRPCListenAddr             = ":8083"
	defaultConfigSyncGRPCKeepaliveTime          = 30 * time.Second
	defaultConfigSyncGRPCKeepaliveTimeout       = 10 * time.Second
	defaultConfigSyncGRPCMinBackoff             = 1 * time.Second
	defaultConfigSyncGRPCMaxBackoff             = 30 * time.Second
	defaultConfigSyncOutboxRetention            = 24 * time.Hour
	defaultConfigSyncOutboxMaxRows        int64 = 10000

	configSyncKeyBytes = 32
)

type Config struct {
	AppEnv           string
	Server           ServerConfig
	Database         DatabaseConfig
	Redis            RedisConfig
	Cache            CacheConfig
	SemanticCache    SemanticCacheConfig
	SessionStore     SessionStoreConfig
	Kafka            KafkaConfig
	Telemetry        TelemetryConfig
	Metrics          MetricsConfig
	Playground       PlaygroundConfig
	Upstream         UpstreamConfig
	Provider         ProviderConfig
	Catalog          CatalogConfig
	CORS             CORSConfig
	Logger           LoggerConfig
	TrustGuard       TrustGuardConfig
	OpenAIModeration OpenAIModerationConfig
	ConfigSync       ConfigSyncConfig
	RateLimit        RateLimitConfig
}

const (
	ConfigSyncAuthModeShared = "shared"
	ConfigSyncAuthModeSigned = "signed"
	// ConfigSyncAuthModeComposite accepts both a signed per-tenant JWT (external
	// data planes → scoped snapshot) and the shared bearer token (in-cluster data
	// plane → global snapshot) on a single control plane.
	ConfigSyncAuthModeComposite = "composite"
)

type ConfigSyncConfig struct {
	DataPlaneEnabled bool
	Token            string // #nosec G117 -- config struct field, not a hardcoded credential
	// TokenPrevious is the prior bearer accepted alongside Token so a token can be
	// rotated without a window where in-flight data planes fail to authenticate.
	TokenPrevious string // #nosec G117 -- config struct field, not a hardcoded credential
	AuthMode      string
	// JWTSecret is the HS256 shared secret used to verify config-sync credentials
	// minted by DataCore. JWTSecretPrevious is the prior secret accepted alongside
	// it so the secret can be rotated without a window where data planes fail to
	// authenticate.
	JWTSecret         string // #nosec G117 -- config struct field, not a hardcoded credential
	JWTSecretPrevious string // #nosec G117 -- config struct field, not a hardcoded credential
	JWTIssuer         string
	JWTAudience       string
	LKGPath           string
	LKGKey            string // #nosec G117 -- config struct field, not a hardcoded credential
	PollInterval      time.Duration
	RecompileDebounce time.Duration
	// RecompileBackstop periodically recompiles even without a write signal so the
	// control plane recovers from a failed boot compile and picks up out-of-band
	// mutations.
	RecompileBackstop time.Duration
	InstanceID        string
	// GRPCEndpoint is the control-plane host:port the data plane dials for the
	// config-sync gRPC transport (ENG-959).
	GRPCEndpoint string
	// GRPCListenAddr is the control-plane listen address for the config-sync gRPC
	// server.
	GRPCListenAddr string
	TLSCAPath      string
	TLSServerName  string
	// TLSInsecure disables transport security on the data-plane dial. It is a
	// dev-only escape hatch and is rejected in deployed environments.
	TLSInsecure          bool
	GRPCTLSCertPath      string
	GRPCTLSKeyPath       string // #nosec G117 -- config struct field, not a hardcoded credential
	GRPCKeepaliveTime    time.Duration
	GRPCKeepaliveTimeout time.Duration
	GRPCMinBackoff       time.Duration
	GRPCMaxBackoff       time.Duration
	OutboxRetention      time.Duration
	OutboxMaxRows        int64
}

type ServerConfig struct {
	AdminPort    int
	ProxyPort    int
	MCPPort      int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	// SecretKey signs and verifies admin-plane JWTs. Empty disables admin auth
	// token acceptance (every token is rejected).
	SecretKey            string
	GatewayBaseDomain    string
	MCPBaseDomain        string
	GatewayDiscoveryMode string
	STSIssuer            string
	STSSigningKey        string
	TrustXFCCFrom        []string
}

type DatabaseConfig struct {
	Login             string
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
	Login             string
	Host              string
	Port              int
	Password          string
	DB                int
	TLSEnabled        bool
	TLSInsecureVerify bool
	Username          string
	CacheName         string
	AWSServerless     bool
}

// CacheConfig drives the in-process TTL cache used by app-layer
// finders. RUN-291 (B.1) will add a parallel Redis-backed layer; the
// finder contract will not change.
type CacheConfig struct {
	LocalTTL time.Duration
}

// SemanticCacheConfig selects the vector store backing the semantic cache
// plugin. VectorStore defaults to "redis".
type SemanticCacheConfig struct {
	VectorStore string
}

type SessionStoreConfig struct {
	Enabled bool
	TTL     time.Duration
}

type KafkaConfig struct {
	Brokers []string
}

type TelemetryConfig struct {
	Enabled             bool
	KafkaTopic          string
	ExportersFile       string
	EnableRequestTraces bool
	EnablePluginTraces  bool
	OTLP                OTLPConfig
}

// OTLPConfig holds process-level OTLP exporter defaults read from the standard
// OTEL_EXPORTER_OTLP_* environment variables. Per-gateway telemetry settings
// override any field present in the gateway configuration.
type OTLPConfig struct {
	Endpoint    string
	Headers     map[string]string
	Protocol    string
	Timeout     time.Duration
	Insecure    bool
	Compression string
}

type MetricsConfig struct {
	Enabled       bool
	QueueSize     int
	WorkerCount   int
	FlushInterval time.Duration
}

// PlaygroundConfig drives the default Redis-backed trace store that lets the
// dashboard playground fetch the metrics Event for a request it just made.
// Only requests carrying the playground token are stored, with a short TTL.
type PlaygroundConfig struct {
	TraceStoreEnabled bool
	TraceStoreTTL     time.Duration
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
	ModelsDevBaseURL string
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
	Level       slog.Level
	Format      string
	FileEnabled bool
}

type TrustGuardConfig struct {
	BaseURL      string
	Timeout      time.Duration
	ClientID     string
	ClientSecret string
}

type OpenAIModerationConfig struct {
	BaseURL string
	Timeout time.Duration
}

// RateLimitConfig gates the per-gateway plan rate limiter.
type RateLimitConfig struct {
	Enabled bool
	// EntitlementsMutable lets tenant-scoped callers set entitlements; off by default so only platform admins can.
	EntitlementsMutable bool
}

func LoadConfig() (*Config, error) {
	cfg := &Config{
		AppEnv:           getEnv("APP_ENV", defaultAppEnv),
		Server:           getServerConfig(),
		Database:         getDatabaseConfig(),
		Redis:            getRedisConfig(),
		Cache:            getCacheConfig(),
		SemanticCache:    getSemanticCacheConfig(),
		SessionStore:     getSessionStoreConfig(),
		Kafka:            getKafkaConfig(),
		Telemetry:        getTelemetryConfig(),
		Metrics:          getMetricsConfig(),
		Playground:       getPlaygroundConfig(),
		Upstream:         getUpstreamConfig(),
		Provider:         getProviderConfig(),
		Catalog:          getCatalogConfig(),
		CORS:             getCORSConfig(),
		Logger:           getLoggerConfig(),
		TrustGuard:       getTrustGuardConfig(),
		OpenAIModeration: getOpenAIModerationConfig(),
		ConfigSync:       getConfigSyncConfig(),
		RateLimit:        getRateLimitConfig(),
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
		MCPPort:      getEnvInt("SERVER_MCP_PORT", defaultServerMCPPort),
		ReadTimeout:  getEnvDuration("SERVER_READ_TIMEOUT", defaultServerReadTimeout),
		WriteTimeout: getEnvDuration("SERVER_WRITE_TIMEOUT", defaultServerWriteTimeout),
		IdleTimeout:  getEnvDuration("SERVER_IDLE_TIMEOUT", defaultServerIdleTimeout),
		SecretKey:    getEnv("SERVER_SECRET_KEY", ""),
		GatewayBaseDomain: getEnv(
			"GATEWAY_BASE_DOMAIN",
			defaultGatewayBaseDomain,
		),
		MCPBaseDomain: getEnv(
			"MCP_BASE_DOMAIN",
			defaultMCPBaseDomain,
		),
		GatewayDiscoveryMode: strings.ToLower(strings.TrimSpace(getEnv(
			"GATEWAY_DISCOVERY_MODE",
			GatewayDiscoveryModeHeader,
		))),
		STSIssuer:     getEnv("STS_ISSUER", "trustgate"),
		STSSigningKey: getEnv("STS_SIGNING_KEY", ""),
		TrustXFCCFrom: splitCSV(getEnv("TRUST_XFCC_FROM", "")),
	}
}

func getDatabaseConfig() DatabaseConfig {
	login := normalizePostgresLogin(os.Getenv("POSTGRES_LOGIN"))
	password := getEnv("DB_PASSWORD", defaultDBPassword)
	if login == postgresLoginAWS {
		password = ""
	}

	return DatabaseConfig{
		Login:             login,
		Host:              getEnv("DB_HOST", defaultDBHost),
		Port:              getEnvInt("DB_PORT", defaultDBPort),
		User:              getEnv("DB_USER", defaultDBUser),
		Password:          password,
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

func normalizePostgresLogin(login string) string {
	normalized := strings.ToLower(strings.TrimSpace(login))
	if normalized == "" {
		return postgresLoginDefault
	}
	return normalized
}

func getRedisConfig() RedisConfig {
	login := normalizeRedisLogin(os.Getenv("REDIS_LOGIN"))
	password := getEnv("REDIS_PASSWORD", "")
	if login == redisLoginAWS {
		password = ""
	}

	return RedisConfig{
		Login:             login,
		Host:              getEnv("REDIS_HOST", defaultRedisHost),
		Port:              getEnvInt("REDIS_PORT", defaultRedisPort),
		Password:          password,
		DB:                getEnvInt("REDIS_DB", defaultRedisDB),
		TLSEnabled:        getEnvBool("REDIS_TLS_ENABLED", defaultRedisTLS),
		TLSInsecureVerify: getEnvBool("REDIS_TLS_INSECURE_VERIFY", false),
		Username:          strings.TrimSpace(getEnv("REDIS_USERNAME", "")),
		CacheName:         strings.TrimSpace(getEnv("REDIS_CACHE_NAME", "")),
		AWSServerless:     getEnvBool("REDIS_AWS_SERVERLESS", false),
	}
}

func normalizeRedisLogin(login string) string {
	normalized := strings.ToLower(strings.TrimSpace(login))
	if normalized == "" {
		return redisLoginDefault
	}
	return normalized
}

func getCacheConfig() CacheConfig {
	return CacheConfig{
		LocalTTL: getEnvDuration("CACHE_LOCAL_TTL", defaultCacheLocalTTL),
	}
}

func getSemanticCacheConfig() SemanticCacheConfig {
	return SemanticCacheConfig{
		VectorStore: getEnv("SEMANTIC_CACHE_VECTOR_STORE", defaultSemanticCacheVectorStore),
	}
}

func getSessionStoreConfig() SessionStoreConfig {
	return SessionStoreConfig{
		Enabled: getEnvBool("SESSION_STORE_ENABLED", defaultSessionStoreEnabled),
		TTL:     getEnvDuration("SESSION_STORE_TTL", defaultSessionStoreTTL),
	}
}

func getKafkaConfig() KafkaConfig {
	return KafkaConfig{Brokers: splitCSV(getEnv("KAFKA_BROKERS", defaultKafkaBrokers))}
}

func getTelemetryConfig() TelemetryConfig {
	return TelemetryConfig{
		Enabled:             getEnvBool("TELEMETRY_ENABLED", defaultTelemetryEnabled),
		KafkaTopic:          getEnv("TELEMETRY_KAFKA_TOPIC", defaultTelemetryKafkaTopic),
		ExportersFile:       getEnv("TELEMETRY_EXPORTERS_FILE", defaultTelemetryExportersFile),
		EnableRequestTraces: getEnvBool("TELEMETRY_ENABLE_REQUEST_TRACES", defaultTelemetryEnableRequestTraces),
		EnablePluginTraces:  getEnvBool("TELEMETRY_ENABLE_PLUGIN_TRACES", defaultTelemetryEnablePluginTraces),
		OTLP:                getOTLPConfig(),
	}
}

func getOTLPConfig() OTLPConfig {
	return OTLPConfig{
		Endpoint:    getEnv("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
		Headers:     parseOTLPHeaders(getEnv("OTEL_EXPORTER_OTLP_HEADERS", "")),
		Protocol:    getEnv("OTEL_EXPORTER_OTLP_PROTOCOL", ""),
		Timeout:     getOTLPTimeout(),
		Insecure:    getEnvBool("OTEL_EXPORTER_OTLP_INSECURE", false),
		Compression: getEnv("OTEL_EXPORTER_OTLP_COMPRESSION", ""),
	}
}

// getOTLPTimeout reads OTEL_EXPORTER_OTLP_TIMEOUT. Per the OpenTelemetry spec the
// value is an integer number of milliseconds; a Go duration string (such as
// "10s") is also accepted for convenience. Returns 0 when unset or invalid so
// the exporter applies its own default.
func getOTLPTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TIMEOUT"))
	if raw == "" {
		return 0
	}
	if ms, err := strconv.Atoi(raw); err == nil {
		if ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	} else if parsed, perr := time.ParseDuration(raw); perr == nil && parsed > 0 {
		return parsed
	}
	slog.Warn("invalid OTEL_EXPORTER_OTLP_TIMEOUT, falling back to default",
		slog.String("value", sanitizeLogValue(raw)))
	return 0
}

// parseOTLPHeaders parses the standard OTEL_EXPORTER_OTLP_HEADERS format
// ("key1=value1,key2=value2") into a map. Malformed pairs are skipped.
func parseOTLPHeaders(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		key, value, ok := strings.Cut(pair, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			continue
		}
		out[key] = strings.TrimSpace(value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func getMetricsConfig() MetricsConfig {
	return MetricsConfig{
		Enabled:       getEnvBool("METRICS_ENABLED", defaultMetricsEnabled),
		QueueSize:     getEnvInt("METRICS_QUEUE_SIZE", defaultMetricsQueueSize),
		WorkerCount:   getEnvInt("METRICS_WORKER_COUNT", defaultMetricsWorkerCount),
		FlushInterval: getEnvDuration("METRICS_FLUSH_INTERVAL", defaultMetricsFlushInterval),
	}
}

func getPlaygroundConfig() PlaygroundConfig {
	ttl := getEnvDuration("PLAYGROUND_TRACE_STORE_TTL", defaultPlaygroundTraceStoreTTL)
	if ttl <= 0 {
		ttl = defaultPlaygroundTraceStoreTTL
	}
	return PlaygroundConfig{
		TraceStoreEnabled: getEnvBool("PLAYGROUND_TRACE_STORE_ENABLED", defaultPlaygroundTraceStoreEnabled),
		TraceStoreTTL:     ttl,
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
		ModelsDevBaseURL: getEnv("MODELS_DEV_BASE_URL", ""),
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
		Level:       getLogLevel(),
		Format:      getEnv("LOG_FORMAT", defaultLogFormat),
		FileEnabled: getEnvBool("LOG_FILE_ENABLED", defaultLogFileEnabled),
	}
}

func getTrustGuardConfig() TrustGuardConfig {
	return TrustGuardConfig{
		BaseURL:      getEnv("TRUSTGUARD_BASE_URL", ""),
		Timeout:      getEnvDuration("TRUSTGUARD_TIMEOUT", defaultTrustGuardTimeout),
		ClientID:     getEnv("TRUSTGUARD_CLIENT_ID", ""),
		ClientSecret: getEnv("TRUSTGUARD_CLIENT_SECRET", ""),
	}
}

func getOpenAIModerationConfig() OpenAIModerationConfig {
	return OpenAIModerationConfig{
		BaseURL: getEnv("OPENAI_MODERATION_BASE_URL", "https://api.openai.com"),
		Timeout: getEnvDuration("OPENAI_MODERATION_TIMEOUT", defaultOpenAIModerationTimeout),
	}
}

func getConfigSyncConfig() ConfigSyncConfig {
	return ConfigSyncConfig{
		DataPlaneEnabled:     getEnvBool("CONFIG_SYNC_DATA_PLANE_ENABLED", defaultConfigSyncDataPlaneEnabled),
		Token:                getEnv("CONFIG_SYNC_TOKEN", ""),
		TokenPrevious:        getEnv("CONFIG_SYNC_TOKEN_PREVIOUS", ""),
		AuthMode:             normalizeConfigSyncAuthMode(getEnv("CONFIG_SYNC_AUTH_MODE", ConfigSyncAuthModeShared)),
		JWTSecret:            getEnv("CONFIG_SYNC_JWT_SECRET", ""),
		JWTSecretPrevious:    getEnv("CONFIG_SYNC_JWT_SECRET_PREVIOUS", ""),
		JWTIssuer:            getEnv("CONFIG_SYNC_JWT_ISSUER", ""),
		JWTAudience:          getEnv("CONFIG_SYNC_JWT_AUDIENCE", ""),
		LKGPath:              getEnv("CONFIG_SYNC_LKG_PATH", defaultConfigSyncLKGPath),
		LKGKey:               getEnv("CONFIG_SYNC_LKG_KEY", ""),
		PollInterval:         getEnvDuration("CONFIG_SYNC_POLL_INTERVAL", defaultConfigSyncPollInterval),
		RecompileDebounce:    getEnvDuration("CONFIG_SYNC_RECOMPILE_DEBOUNCE", defaultConfigSyncRecompileDebounce),
		RecompileBackstop:    getEnvDuration("CONFIG_SYNC_RECOMPILE_BACKSTOP", defaultConfigSyncRecompileBackstop),
		InstanceID:           resolveConfigSyncInstanceID(),
		GRPCEndpoint:         getEnv("CONFIG_SYNC_GRPC_ENDPOINT", ""),
		GRPCListenAddr:       getEnv("CONFIG_SYNC_GRPC_LISTEN_ADDR", defaultConfigSyncGRPCListenAddr),
		TLSCAPath:            getEnv("CONFIG_SYNC_TLS_CA", ""),
		TLSServerName:        getEnv("CONFIG_SYNC_TLS_SERVER_NAME", ""),
		TLSInsecure:          getEnvBool("CONFIG_SYNC_TLS_INSECURE", false),
		GRPCTLSCertPath:      getEnv("CONFIG_SYNC_GRPC_TLS_CERT", ""),
		GRPCTLSKeyPath:       getEnv("CONFIG_SYNC_GRPC_TLS_KEY", ""),
		GRPCKeepaliveTime:    getEnvDuration("CONFIG_SYNC_GRPC_KEEPALIVE_TIME", defaultConfigSyncGRPCKeepaliveTime),
		GRPCKeepaliveTimeout: getEnvDuration("CONFIG_SYNC_GRPC_KEEPALIVE_TIMEOUT", defaultConfigSyncGRPCKeepaliveTimeout),
		GRPCMinBackoff:       getEnvDuration("CONFIG_SYNC_GRPC_MIN_BACKOFF", defaultConfigSyncGRPCMinBackoff),
		GRPCMaxBackoff:       getEnvDuration("CONFIG_SYNC_GRPC_MAX_BACKOFF", defaultConfigSyncGRPCMaxBackoff),
		OutboxRetention:      getEnvDuration("CONFIG_SYNC_OUTBOX_RETENTION", defaultConfigSyncOutboxRetention),
		OutboxMaxRows:        getEnvInt64("CONFIG_SYNC_OUTBOX_MAX_ROWS", defaultConfigSyncOutboxMaxRows),
	}
}

func getRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Enabled:             getEnvBool("RATE_LIMIT_ENABLED", defaultRateLimitEnabled),
		EntitlementsMutable: getEnvBool("ENTITLEMENTS_MUTABLE", defaultEntitlementsMutable),
	}
}

func normalizeConfigSyncAuthMode(mode string) string {
	return strings.ToLower(strings.TrimSpace(mode))
}

func resolveConfigSyncInstanceID() string {
	if id := getEnv("CONFIG_SYNC_INSTANCE_ID", ""); id != "" {
		return id
	}
	if host := os.Getenv("HOSTNAME"); host != "" {
		return host
	}
	if host, err := os.Hostname(); err == nil {
		return host
	}
	return ""
}

func DBLessDataPlaneEnabled() bool {
	return getEnvBool("CONFIG_SYNC_DATA_PLANE_ENABLED", defaultConfigSyncDataPlaneEnabled)
}

func (cs ConfigSyncConfig) Validate() error {
	if !cs.DataPlaneEnabled {
		return nil
	}
	if cs.Token == "" {
		return fmt.Errorf("%w: CONFIG_SYNC_TOKEN is required when CONFIG_SYNC_DATA_PLANE_ENABLED is true", errors.ErrInvalidConfig)
	}
	if cs.GRPCEndpoint == "" {
		return fmt.Errorf("%w: CONFIG_SYNC_GRPC_ENDPOINT is required when CONFIG_SYNC_DATA_PLANE_ENABLED is true", errors.ErrInvalidConfig)
	}
	if host, port, err := net.SplitHostPort(cs.GRPCEndpoint); err != nil || host == "" || port == "" {
		return fmt.Errorf("%w: CONFIG_SYNC_GRPC_ENDPOINT must be a well-formed host:port", errors.ErrInvalidConfig)
	}
	if cs.LKGPath == "" {
		return fmt.Errorf("%w: CONFIG_SYNC_LKG_PATH is required when CONFIG_SYNC_DATA_PLANE_ENABLED is true", errors.ErrInvalidConfig)
	}
	key, err := base64.StdEncoding.DecodeString(cs.LKGKey)
	if err != nil || len(key) != configSyncKeyBytes {
		return fmt.Errorf("%w: CONFIG_SYNC_LKG_KEY must be base64 that decodes to exactly 32 bytes (AES-256)", errors.ErrInvalidConfig)
	}
	if cs.PollInterval <= 0 {
		return fmt.Errorf("%w: CONFIG_SYNC_POLL_INTERVAL must be a positive duration", errors.ErrInvalidConfig)
	}
	return nil
}

func (c *Config) Validate() error {
	c.Database.Login = normalizePostgresLogin(c.Database.Login)
	switch c.Database.Login {
	case postgresLoginDefault, postgresLoginAWS:
	default:
		return fmt.Errorf("%w: POSTGRES_LOGIN must be %q or %q", errors.ErrInvalidConfig, postgresLoginDefault, postgresLoginAWS)
	}
	if c.Server.GatewayDiscoveryMode != GatewayDiscoveryModeHeader &&
		c.Server.GatewayDiscoveryMode != GatewayDiscoveryModeSubdomain {
		return fmt.Errorf(
			"%w: GATEWAY_DISCOVERY_MODE must be %q or %q",
			errors.ErrInvalidConfig, GatewayDiscoveryModeHeader, GatewayDiscoveryModeSubdomain,
		)
	}
	if strings.Trim(strings.ToLower(strings.TrimSpace(c.Server.GatewayBaseDomain)), ".") == "" {
		return fmt.Errorf("%w: GATEWAY_BASE_DOMAIN is required", errors.ErrInvalidConfig)
	}
	if !c.ConfigSync.DataPlaneEnabled {
		if c.Database.Host == "" {
			return fmt.Errorf("%w: DB_HOST is required", errors.ErrInvalidConfig)
		}
		if c.Database.User == "" {
			return fmt.Errorf("%w: DB_USER is required", errors.ErrInvalidConfig)
		}
		if c.Database.Name == "" {
			return fmt.Errorf("%w: DB_NAME is required", errors.ErrInvalidConfig)
		}
		if c.Database.Login == postgresLoginAWS {
			c.Database.SSLMode = strings.ToLower(strings.TrimSpace(c.Database.SSLMode))
			if c.Database.SSLMode != "require" && c.Database.SSLMode != "verify-ca" && c.Database.SSLMode != "verify-full" {
				return fmt.Errorf("%w: DB_SSL_MODE must be %q, %q or %q when POSTGRES_LOGIN=%q", errors.ErrInvalidConfig, "require", "verify-ca", "verify-full", postgresLoginAWS)
			}
		}
	}
	c.Redis.Login = normalizeRedisLogin(c.Redis.Login)
	switch c.Redis.Login {
	case redisLoginDefault, redisLoginAWS:
	default:
		return fmt.Errorf("%w: REDIS_LOGIN must be %q or %q", errors.ErrInvalidConfig, redisLoginDefault, redisLoginAWS)
	}
	if c.Redis.Host == "" {
		return fmt.Errorf("%w: REDIS_HOST is required", errors.ErrInvalidConfig)
	}
	if c.Redis.Login == redisLoginAWS {
		c.Redis.Password = ""
		if !c.Redis.TLSEnabled {
			return fmt.Errorf("%w: REDIS_TLS_ENABLED must be true when REDIS_LOGIN=%q", errors.ErrInvalidConfig, redisLoginAWS)
		}
		if c.Redis.CacheName == "" {
			return fmt.Errorf("%w: REDIS_CACHE_NAME is required when REDIS_LOGIN=%q", errors.ErrInvalidConfig, redisLoginAWS)
		}
		if c.Redis.Username == "" {
			return fmt.Errorf("%w: REDIS_USERNAME is required when REDIS_LOGIN=%q", errors.ErrInvalidConfig, redisLoginAWS)
		}
	}
	if len(c.Kafka.Brokers) == 0 {
		return fmt.Errorf("%w: KAFKA_BROKERS must contain at least one broker", errors.ErrInvalidConfig)
	}
	if c.Telemetry.Enabled && c.Telemetry.KafkaTopic == "" {
		return fmt.Errorf("%w: TELEMETRY_KAFKA_TOPIC is required when telemetry is enabled", errors.ErrInvalidConfig)
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
	if c.isDeployed() && c.ConfigSync.DataPlaneEnabled && c.ConfigSync.TLSInsecure {
		return fmt.Errorf("%w: CONFIG_SYNC_TLS_INSECURE must not be true in deployed environments so the config-sync channel is not sent in cleartext", errors.ErrInvalidConfig)
	}
	if err := c.ConfigSync.validateAuthMode(); err != nil {
		return err
	}
	if err := c.ConfigSync.Validate(); err != nil {
		return err
	}
	return nil
}

func (cs ConfigSyncConfig) validateAuthMode() error {
	switch cs.AuthMode {
	case "", ConfigSyncAuthModeShared:
		return nil
	case ConfigSyncAuthModeSigned:
		return cs.validateSignedJWTParams()
	case ConfigSyncAuthModeComposite:
		if cs.Token == "" {
			return fmt.Errorf("%w: CONFIG_SYNC_AUTH_MODE=composite requires CONFIG_SYNC_TOKEN for the in-cluster data plane that pulls the global snapshot", errors.ErrInvalidConfig)
		}
		return cs.validateSignedJWTParams()
	default:
		return fmt.Errorf("%w: CONFIG_SYNC_AUTH_MODE must be %q, %q or %q", errors.ErrInvalidConfig, ConfigSyncAuthModeShared, ConfigSyncAuthModeSigned, ConfigSyncAuthModeComposite)
	}
}

func (cs ConfigSyncConfig) validateSignedJWTParams() error {
	if cs.JWTSecret == "" {
		return fmt.Errorf("%w: CONFIG_SYNC_AUTH_MODE=%s requires CONFIG_SYNC_JWT_SECRET", errors.ErrInvalidConfig, cs.AuthMode)
	}
	if cs.JWTIssuer == "" || cs.JWTAudience == "" {
		return fmt.Errorf("%w: CONFIG_SYNC_AUTH_MODE=%s requires CONFIG_SYNC_JWT_ISSUER and CONFIG_SYNC_JWT_AUDIENCE", errors.ErrInvalidConfig, cs.AuthMode)
	}
	return nil
}

// IsDeployed reports whether APP_ENV marks a non-local deployment (staging or
// production), so plane wiring can enforce deployed-only requirements such as the
// control-plane config-sync gRPC server TLS certificate.
func (c *Config) IsDeployed() bool {
	return c.isDeployed()
}

func (c *Config) isDeployed() bool {
	return isDeployedEnv(c.AppEnv)
}

func isDeployedEnv(appEnv string) bool {
	switch strings.ToLower(strings.TrimSpace(appEnv)) {
	case "prod", "production", "staging", "stage":
		return true
	default:
		return false
	}
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

func getEnvInt64(key string, defaultValue int64) int64 {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 {
		slog.Warn("invalid int64 environment variable, falling back to default",
			slog.String("key", key), slog.String("value", sanitizeLogValue(value)))
		return defaultValue
	}
	return parsed
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
