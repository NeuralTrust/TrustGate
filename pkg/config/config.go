package config

import (
	"os"
	"strconv"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
)

type MetricsConfig struct {
	Enabled           bool
	RetentionDays     int
	EnableLatency     bool
	EnableUpstream    bool
	EnableConnections bool
	EnablePerRoute    bool
}

type Config struct {
	Server    ServerConfig
	Metrics   MetricsConfig
	Database  DatabaseConfig
	Redis     RedisConfig
	Plugins   PluginsConfig
	WebSocket WebSocketConfig
	TLS       TLSConfig
}

type ServerConfig struct {
	AdminPort   int
	ProxyPort   int
	MetricsPort int
	Type        string
	Port        int
	Host        string
	SecretKey   string
}

type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type RedisConfig struct {
	Host          string
	Port          int
	Password      string
	DB            int
	TLS           bool
	EventsChannel string
}

type PluginsConfig struct {
	IgnoreErrors bool
}

type WebSocketConfig struct {
	MaxConnections int
	PingPeriod     string
	PongWait       string
}

type TLSConfig struct {
	Disabled            bool
	EnableMTLS          bool
	DisableSystemCAPool bool
	CACert              string
	Keys                TLSKeyPair
	CipherSuites        []uint16
	CurvePreferences    []uint16
	MinVersion          string
	MaxVersion          string
	CertsBasePath       string
}

type TLSKeyPair struct {
	PublicKey  string
	PrivateKey string
}

var globalConfig *Config

func Load() (*Config, error) {
	// Server configuration
	serverAdminPort, _ := strconv.Atoi(getEnv("SERVER_ADMIN_PORT", "8080"))
	serverProxyPort, _ := strconv.Atoi(getEnv("SERVER_PROXY_PORT", "8081"))
	serverMetricsPort, _ := strconv.Atoi(getEnv("SERVER_METRICS_PORT", "9090"))
	serverSecretKey := getEnv("SERVER_SECRET_KEY", "")

	// Metrics configuration
	metricsEnabled := getEnvBool("METRICS_ENABLED", true)
	metricsRetentionDays, _ := strconv.Atoi(getEnv("METRICS_RETENTION_DAYS", "30"))
	metricsEnableLatency := getEnvBool("METRICS_ENABLE_LATENCY", true)
	metricsEnableUpstream := getEnvBool("METRICS_ENABLE_UPSTREAM", true)
	metricsEnableConnections := getEnvBool("METRICS_ENABLE_CONNECTIONS", true)
	metricsEnablePerRoute := getEnvBool("METRICS_ENABLE_PER_ROUTE", true)

	// Database configuration
	databaseHost := getEnv("DATABASE_HOST", "localhost")
	databasePort, _ := strconv.Atoi(getEnv("DATABASE_PORT", "5432"))
	databaseUser := getEnv("DATABASE_USER", "postgres")
	databasePassword := getEnv("DATABASE_PASSWORD", "")
	databaseName := getEnv("DATABASE_NAME", "trustgate")
	databaseSSLMode := getEnv("DATABASE_SSL_MODE", "disable")

	// Redis configuration
	redisHost := getEnv("REDIS_HOST", "localhost")
	redisPort, _ := strconv.Atoi(getEnv("REDIS_PORT", "6379"))
	redisPassword := getEnv("REDIS_PASSWORD", "")
	redisDB, _ := strconv.Atoi(getEnv("REDIS_DB", "0"))
	redisTLS := getEnvBool("REDIS_TLS", false)
	redisEventsChannel := getEnv("REDIS_EVENTS_CHANNEL", string(channel.GatewayEventsChannel))

	// Plugins configuration
	pluginsIgnoreErrors := getEnvBool("PLUGINS_IGNORE_ERRORS", true)

	// WebSocket configuration
	websocketMaxConnections, _ := strconv.Atoi(getEnv("WEBSOCKET_MAX_CONNECTIONS", "1000"))
	websocketPingPeriod := getEnv("WEBSOCKET_PING_PERIOD", "30s")
	websocketPongWait := getEnv("WEBSOCKET_PONG_WAIT", "2m")

	// TLS configuration
	tlsDisabled := getEnvBool("TLS_DISABLED", true)
	tlsEnableMTLS := getEnvBool("TLS_ENABLE_MTLS", true)
	tlsDisableSystemCAPool := getEnvBool("TLS_DISABLE_SYSTEM_CA_POOL", false)
	tlsCACert := getEnv("TLS_CA_CERT", "")
	tlsPublicKey := getEnv("TLS_KEYS_PUBLIC_KEY", "")
	tlsPrivateKey := getEnv("TLS_KEYS_PRIVATE_KEY", "")
	tlsMinVersion := getEnv("TLS_MIN_VERSION", "TLS12")
	tlsMaxVersion := getEnv("TLS_MAX_VERSION", "TLS13")
	tlsCipherSuites := parseUint16Slice(getEnv("TLS_CIPHER_SUITES", "4865,4866,4867"))
	tlsCurvePreferences := parseUint16Slice(getEnv("TLS_CURVE_PREFERENCES", "23,24,25"))
	tlsCertsBasePath := getEnv("TLS_CERTS_BASE_PATH", "/tmp/certs")

	config := &Config{
		Server: ServerConfig{
			AdminPort:   serverAdminPort,
			ProxyPort:   serverProxyPort,
			MetricsPort: serverMetricsPort,
			SecretKey:   serverSecretKey,
		},
		Metrics: MetricsConfig{
			Enabled:           metricsEnabled,
			RetentionDays:     metricsRetentionDays,
			EnableLatency:     metricsEnableLatency,
			EnableUpstream:    metricsEnableUpstream,
			EnableConnections: metricsEnableConnections,
			EnablePerRoute:    metricsEnablePerRoute,
		},
		Database: DatabaseConfig{
			Host:     databaseHost,
			Port:     databasePort,
			User:     databaseUser,
			Password: databasePassword,
			DBName:   databaseName,
			SSLMode:  databaseSSLMode,
		},
		Redis: RedisConfig{
			Host:          redisHost,
			Port:          redisPort,
			Password:      redisPassword,
			DB:            redisDB,
			TLS:           redisTLS,
			EventsChannel: redisEventsChannel,
		},
		Plugins: PluginsConfig{
			IgnoreErrors: pluginsIgnoreErrors,
		},
		WebSocket: WebSocketConfig{
			MaxConnections: websocketMaxConnections,
			PingPeriod:     websocketPingPeriod,
			PongWait:       websocketPongWait,
		},
		TLS: TLSConfig{
			Disabled:            tlsDisabled,
			EnableMTLS:          tlsEnableMTLS,
			DisableSystemCAPool: tlsDisableSystemCAPool,
			CACert:              tlsCACert,
			Keys: TLSKeyPair{
				PublicKey:  tlsPublicKey,
				PrivateKey: tlsPrivateKey,
			},
			CipherSuites:     tlsCipherSuites,
			CurvePreferences: tlsCurvePreferences,
			MinVersion:       tlsMinVersion,
			MaxVersion:       tlsMaxVersion,
			CertsBasePath:    tlsCertsBasePath,
		},
	}

	globalConfig = config

	return config, nil
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return defaultValue
	}
	return parsed
}

func parseUint16Slice(s string) []uint16 {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]uint16, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			continue
		}
		result = append(result, uint16(v))
	}
	return result
}

func GetConfig() *Config {
	return globalConfig
}
