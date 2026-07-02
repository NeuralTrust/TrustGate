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

package config

import (
	"encoding/base64"
	stderrors "errors"
	"log/slog"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

func minimumEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DB_HOST", "db.example")
	t.Setenv("DB_USER", "u")
	t.Setenv("DB_NAME", "n")
	t.Setenv("REDIS_HOST", "redis.example")
	t.Setenv("KAFKA_BROKERS", "kafka.example:9092")
}

func TestLoadConfig_AppliesDefaults(t *testing.T) {
	minimumEnv(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Server.AdminPort != defaultServerAdminPort {
		t.Errorf("AdminPort default = %d, want %d", cfg.Server.AdminPort, defaultServerAdminPort)
	}
	if cfg.Server.ProxyPort != defaultServerProxyPort {
		t.Errorf("ProxyPort default = %d, want %d", cfg.Server.ProxyPort, defaultServerProxyPort)
	}
	if cfg.Logger.Level != slog.LevelInfo {
		t.Errorf("Logger.Level default = %v, want INFO", cfg.Logger.Level)
	}
	if cfg.Database.MinConns != defaultDBMinConns {
		t.Errorf("DB.MinConns default = %d, want %d", cfg.Database.MinConns, defaultDBMinConns)
	}
	if cfg.Database.MaxConns != defaultDBMaxConns {
		t.Errorf("DB.MaxConns default = %d, want %d", cfg.Database.MaxConns, defaultDBMaxConns)
	}
}

func TestLoadConfig_EnvOverridesDefault(t *testing.T) {
	minimumEnv(t)
	t.Setenv("SERVER_ADMIN_PORT", "9090")
	t.Setenv("DB_MAX_CONNS", "50")
	t.Setenv("LOG_LEVEL", "DEBUG")
	t.Setenv("KAFKA_BROKERS", "k1:9092,k2:9092, k3:9092 ")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Server.AdminPort != 9090 {
		t.Errorf("AdminPort = %d, want 9090", cfg.Server.AdminPort)
	}
	if cfg.Database.MaxConns != 50 {
		t.Errorf("DB.MaxConns = %d, want 50", cfg.Database.MaxConns)
	}
	if cfg.Logger.Level != slog.LevelDebug {
		t.Errorf("Logger.Level = %v, want DEBUG", cfg.Logger.Level)
	}
	if got, want := len(cfg.Kafka.Brokers), 3; got != want {
		t.Fatalf("Kafka.Brokers len = %d, want %d", got, want)
	}
	if cfg.Kafka.Brokers[2] != "k3:9092" {
		t.Errorf("Kafka.Brokers[2] = %q, want trimmed %q", cfg.Kafka.Brokers[2], "k3:9092")
	}
}

func TestLoadConfig_DurationOverride(t *testing.T) {
	minimumEnv(t)
	t.Setenv("DB_MAX_CONN_LIFETIME", "2h30m")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if want := 2*time.Hour + 30*time.Minute; cfg.Database.MaxConnLifetime != want {
		t.Errorf("MaxConnLifetime = %v, want %v", cfg.Database.MaxConnLifetime, want)
	}
}

func TestLoadConfig_InvalidIntFallsBack(t *testing.T) {
	minimumEnv(t)
	t.Setenv("SERVER_ADMIN_PORT", "not-a-number")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Server.AdminPort != defaultServerAdminPort {
		t.Errorf("AdminPort fell back to %d, want %d", cfg.Server.AdminPort, defaultServerAdminPort)
	}
}

func TestLoadConfig_CORSDefaultsAndOverride(t *testing.T) {
	minimumEnv(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got, want := cfg.CORS.AllowOrigins, []string{"*"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("default CORS.AllowOrigins = %v, want %v", got, want)
	}
	if cfg.CORS.AllowCredentials {
		t.Errorf("default CORS.AllowCredentials = true, want false")
	}

	t.Setenv("CORS_ALLOW_ORIGINS", "https://app.example, https://admin.example")
	t.Setenv("CORS_ALLOW_CREDENTIALS", "true")
	t.Setenv("CORS_MAX_AGE", "3600")

	cfg, err = LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig with overrides: %v", err)
	}
	if got, want := len(cfg.CORS.AllowOrigins), 2; got != want {
		t.Fatalf("CORS.AllowOrigins len = %d, want %d", got, want)
	}
	if cfg.CORS.AllowOrigins[1] != "https://admin.example" {
		t.Errorf("CORS.AllowOrigins[1] = %q, want trimmed %q", cfg.CORS.AllowOrigins[1], "https://admin.example")
	}
	if !cfg.CORS.AllowCredentials {
		t.Errorf("CORS.AllowCredentials = false, want true")
	}
	if cfg.CORS.MaxAge != "3600" {
		t.Errorf("CORS.MaxAge = %q, want %q", cfg.CORS.MaxAge, "3600")
	}
}

func TestLoadConfig_B1RuntimeDefaultsAndOverrides(t *testing.T) {
	minimumEnv(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Redis.TLSEnabled {
		t.Errorf("Redis.TLSEnabled default = true, want false")
	}
	if cfg.Telemetry.KafkaTopic != defaultTelemetryKafkaTopic {
		t.Errorf("Telemetry.KafkaTopic = %q, want %q", cfg.Telemetry.KafkaTopic, defaultTelemetryKafkaTopic)
	}
	if cfg.Metrics.QueueSize != defaultMetricsQueueSize {
		t.Errorf("Metrics.QueueSize = %d, want %d", cfg.Metrics.QueueSize, defaultMetricsQueueSize)
	}
	if cfg.Upstream.Timeout != defaultUpstreamTimeout {
		t.Errorf("Upstream.Timeout = %v, want %v", cfg.Upstream.Timeout, defaultUpstreamTimeout)
	}
	if cfg.Provider.MaxRetries != defaultProviderMaxRetries {
		t.Errorf("Provider.MaxRetries = %d, want %d", cfg.Provider.MaxRetries, defaultProviderMaxRetries)
	}

	t.Setenv("REDIS_TLS_ENABLED", "true")
	t.Setenv("REDIS_TLS_INSECURE_VERIFY", "true")
	t.Setenv("TELEMETRY_KAFKA_TOPIC", "custom.requests")
	t.Setenv("METRICS_QUEUE_SIZE", "42")
	t.Setenv("METRICS_WORKER_COUNT", "3")
	t.Setenv("METRICS_FLUSH_INTERVAL", "250ms")
	t.Setenv("UPSTREAM_TIMEOUT", "12s")
	t.Setenv("UPSTREAM_ERROR_PASSTHROUGH", "false")
	t.Setenv("PROVIDER_REQUEST_TIMEOUT", "9s")
	t.Setenv("PROVIDER_MAX_RETRIES", "5")

	cfg, err = LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig with overrides: %v", err)
	}
	if !cfg.Redis.TLSEnabled || !cfg.Redis.TLSInsecureVerify {
		t.Errorf("Redis TLS override not applied: %+v", cfg.Redis)
	}
	if cfg.Telemetry.KafkaTopic != "custom.requests" {
		t.Errorf("Telemetry override not applied: %+v", cfg.Telemetry)
	}
	if cfg.Metrics.QueueSize != 42 || cfg.Metrics.WorkerCount != 3 || cfg.Metrics.FlushInterval != 250*time.Millisecond {
		t.Errorf("Metrics override not applied: %+v", cfg.Metrics)
	}
	if cfg.Upstream.Timeout != 12*time.Second || cfg.Upstream.ErrorPassthrough {
		t.Errorf("Upstream override not applied: %+v", cfg.Upstream)
	}
	if cfg.Provider.RequestTimeout != 9*time.Second || cfg.Provider.MaxRetries != 5 {
		t.Errorf("Provider override not applied: %+v", cfg.Provider)
	}
}

func TestLoadConfig_OTLPDefaultsAndOverrides(t *testing.T) {
	minimumEnv(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Telemetry.OTLP.Endpoint != "" {
		t.Errorf("OTLP.Endpoint default = %q, want empty", cfg.Telemetry.OTLP.Endpoint)
	}
	if cfg.Telemetry.OTLP.Timeout != 0 {
		t.Errorf("OTLP.Timeout default = %v, want 0", cfg.Telemetry.OTLP.Timeout)
	}

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "collector:4317")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer x,team=core")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", "15000")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip")

	cfg, err = LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig with OTLP overrides: %v", err)
	}
	otlp := cfg.Telemetry.OTLP
	if otlp.Endpoint != "collector:4317" {
		t.Errorf("OTLP.Endpoint = %q", otlp.Endpoint)
	}
	if otlp.Protocol != "http/protobuf" {
		t.Errorf("OTLP.Protocol = %q", otlp.Protocol)
	}
	if otlp.Timeout != 15*time.Second {
		t.Errorf("OTLP.Timeout = %v, want 15s", otlp.Timeout)
	}
	if !otlp.Insecure {
		t.Errorf("OTLP.Insecure = false, want true")
	}
	if otlp.Compression != "gzip" {
		t.Errorf("OTLP.Compression = %q", otlp.Compression)
	}
	if otlp.Headers["authorization"] != "Bearer x" || otlp.Headers["team"] != "core" {
		t.Errorf("OTLP.Headers = %v", otlp.Headers)
	}
}

func TestParseOTLPHeaders(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{"empty", "", nil},
		{"single", "a=1", map[string]string{"a": "1"}},
		{"multi with spaces", " a = 1 , b=2 ", map[string]string{"a": "1", "b": "2"}},
		{"skips malformed", "a=1,noequals,=novalue,b=2", map[string]string{"a": "1", "b": "2"}},
		{"empty value kept", "a=", map[string]string{"a": ""}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseOTLPHeaders(tc.raw)
			if len(got) != len(tc.want) {
				t.Fatalf("parseOTLPHeaders(%q) = %v, want %v", tc.raw, got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("key %q = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestGetOTLPTimeout(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{"unset", "", 0},
		{"milliseconds", "15000", 15 * time.Second},
		{"go duration", "5s", 5 * time.Second},
		{"zero", "0", 0},
		{"negative ms", "-5", 0},
		{"garbage", "abc", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_TIMEOUT", tc.value)
			if got := getOTLPTimeout(); got != tc.want {
				t.Errorf("getOTLPTimeout(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestLoadConfig_TrustGuardDefaults(t *testing.T) {
	minimumEnv(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.TrustGuard.BaseURL != "" {
		t.Errorf("TrustGuard.BaseURL default = %q, want empty", cfg.TrustGuard.BaseURL)
	}
	if cfg.TrustGuard.Timeout != defaultTrustGuardTimeout {
		t.Errorf("TrustGuard.Timeout default = %v, want %v", cfg.TrustGuard.Timeout, defaultTrustGuardTimeout)
	}
}

func TestLoadConfig_TrustGuardEnvOverrides(t *testing.T) {
	minimumEnv(t)
	t.Setenv("TRUSTGUARD_BASE_URL", "https://guard.example")
	t.Setenv("TRUSTGUARD_TIMEOUT", "30s")
	t.Setenv("TRUSTGUARD_CLIENT_ID", "tgc_gateway")
	t.Setenv("TRUSTGUARD_CLIENT_SECRET", "super-secret")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.TrustGuard.BaseURL != "https://guard.example" {
		t.Errorf("TrustGuard.BaseURL = %q, want %q", cfg.TrustGuard.BaseURL, "https://guard.example")
	}
	if cfg.TrustGuard.Timeout != 30*time.Second {
		t.Errorf("TrustGuard.Timeout = %v, want %v", cfg.TrustGuard.Timeout, 30*time.Second)
	}
	if cfg.TrustGuard.ClientID != "tgc_gateway" {
		t.Errorf("TrustGuard.ClientID = %q, want %q", cfg.TrustGuard.ClientID, "tgc_gateway")
	}
	if cfg.TrustGuard.ClientSecret != "super-secret" {
		t.Errorf("TrustGuard.ClientSecret = %q, want %q", cfg.TrustGuard.ClientSecret, "super-secret")
	}
}

func TestLoadConfig_TrustGuardMalformedTimeoutFallsBack(t *testing.T) {
	minimumEnv(t)
	t.Setenv("TRUSTGUARD_TIMEOUT", "not-a-duration")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.TrustGuard.Timeout != defaultTrustGuardTimeout {
		t.Errorf("TrustGuard.Timeout fell back to %v, want %v", cfg.TrustGuard.Timeout, defaultTrustGuardTimeout)
	}
}

func TestLoadConfig_KafkaBrokersAllBlankFailsValidation(t *testing.T) {
	minimumEnv(t)
	t.Setenv("KAFKA_BROKERS", " , , ")

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected validation error for blank KAFKA_BROKERS")
	}
	if !stderrors.Is(err, errors.ErrInvalidConfig) {
		t.Errorf("error %v is not ErrInvalidConfig", err)
	}
}

func valid() *Config {
	return &Config{
		Database: DatabaseConfig{Host: "db", User: "u", Name: "n"},
		Redis:    RedisConfig{Host: "r"},
		Kafka:    KafkaConfig{Brokers: []string{"k:9092"}},
	}
}

func validServer() ServerConfig {
	return ServerConfig{
		GatewayDiscoveryMode: GatewayDiscoveryModeHeader,
		GatewayBaseDomain:    "gw.example",
	}
}

func postgresValid() *Config {
	return &Config{
		Server:   validServer(),
		Database: DatabaseConfig{Host: "db", User: "u", Name: "n"},
		Redis:    RedisConfig{Host: "r"},
		Kafka:    KafkaConfig{Brokers: []string{"k:9092"}},
	}
}

func aes256Key() string {
	return base64.StdEncoding.EncodeToString(make([]byte, configSyncKeyBytes))
}

func dbLessValid() *Config {
	return &Config{
		Server: validServer(),
		Redis:  RedisConfig{Host: "r"},
		Kafka:  KafkaConfig{Brokers: []string{"k:9092"}},
		ConfigSync: ConfigSyncConfig{
			DataPlaneEnabled: true,
			Token:            "config-sync-token",
			GRPCEndpoint:     "control.example:8083",
			LKGPath:          defaultConfigSyncLKGPath,
			LKGKey:           aes256Key(),
			PollInterval:     5 * time.Minute,
		},
	}
}

func TestValidate_RejectsBlankRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		mut  func(c *Config)
	}{
		{"DB_HOST", func(c *Config) { c.Database.Host = "" }},
		{"DB_USER", func(c *Config) { c.Database.User = "" }},
		{"DB_NAME", func(c *Config) { c.Database.Name = "" }},
		{"REDIS_HOST", func(c *Config) { c.Redis.Host = "" }},
		{"KAFKA_BROKERS", func(c *Config) { c.Kafka.Brokers = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid()
			tc.mut(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation error when %s is blank", tc.name)
			}
			if !stderrors.Is(err, errors.ErrInvalidConfig) {
				t.Errorf("error %v is not ErrInvalidConfig", err)
			}
		})
	}
}

func TestValidate_PostgresGraphStillValidates(t *testing.T) {
	if err := postgresValid().Validate(); err != nil {
		t.Fatalf("postgres graph should validate: %v", err)
	}
}

func TestValidate_DBLessSkipsDatabaseFields(t *testing.T) {
	cfg := dbLessValid()
	if cfg.Database.Host != "" || cfg.Database.User != "" || cfg.Database.Name != "" {
		t.Fatal("dbLessValid should leave DB fields blank")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DB-less data plane should validate with blank DB_*: %v", err)
	}
}

func TestValidate_DBLessRequiresConfigSync(t *testing.T) {
	tests := []struct {
		name string
		mut  func(cs *ConfigSyncConfig)
	}{
		{"missing token", func(cs *ConfigSyncConfig) { cs.Token = "" }},
		{"missing grpc endpoint", func(cs *ConfigSyncConfig) { cs.GRPCEndpoint = "" }},
		{"malformed grpc endpoint", func(cs *ConfigSyncConfig) { cs.GRPCEndpoint = "not-a-host-port" }},
		{"grpc endpoint missing port", func(cs *ConfigSyncConfig) { cs.GRPCEndpoint = "control.example" }},
		{"missing lkg path", func(cs *ConfigSyncConfig) { cs.LKGPath = "" }},
		{"key not base64", func(cs *ConfigSyncConfig) { cs.LKGKey = "!!!not-base64!!!" }},
		{"key wrong length", func(cs *ConfigSyncConfig) {
			cs.LKGKey = base64.StdEncoding.EncodeToString(make([]byte, 16))
		}},
		{"empty key", func(cs *ConfigSyncConfig) { cs.LKGKey = "" }},
		{"non-positive poll", func(cs *ConfigSyncConfig) { cs.PollInterval = 0 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dbLessValid()
			tc.mut(&cfg.ConfigSync)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
			if !stderrors.Is(err, errors.ErrInvalidConfig) {
				t.Errorf("error %v is not ErrInvalidConfig", err)
			}
		})
	}
}

func TestValidate_DBLessAcceptsValid32ByteKey(t *testing.T) {
	if err := dbLessValid().ConfigSync.Validate(); err != nil {
		t.Fatalf("valid 32-byte config-sync should pass: %v", err)
	}
}

func TestValidate_DBLessStillRequiresRedisAndKafka(t *testing.T) {
	tests := []struct {
		name string
		mut  func(c *Config)
	}{
		{"REDIS_HOST", func(c *Config) { c.Redis.Host = "" }},
		{"KAFKA_BROKERS", func(c *Config) { c.Kafka.Brokers = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dbLessValid()
			tc.mut(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation error when %s is blank on DB-less data plane", tc.name)
			}
			if !stderrors.Is(err, errors.ErrInvalidConfig) {
				t.Errorf("error %v is not ErrInvalidConfig", err)
			}
		})
	}
}

func TestConfigSyncValidate_DisabledIsInert(t *testing.T) {
	cs := ConfigSyncConfig{DataPlaneEnabled: false}
	if err := cs.Validate(); err != nil {
		t.Fatalf("config-sync validation should be a no-op when disabled: %v", err)
	}
}

func TestLoadConfig_ConfigSyncDefaults(t *testing.T) {
	minimumEnv(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ConfigSync.DataPlaneEnabled {
		t.Errorf("ConfigSync.DataPlaneEnabled default = true, want false")
	}
	if cfg.ConfigSync.PollInterval != defaultConfigSyncPollInterval {
		t.Errorf("ConfigSync.PollInterval = %v, want %v", cfg.ConfigSync.PollInterval, defaultConfigSyncPollInterval)
	}
	if cfg.ConfigSync.RecompileDebounce != defaultConfigSyncRecompileDebounce {
		t.Errorf("ConfigSync.RecompileDebounce = %v, want %v", cfg.ConfigSync.RecompileDebounce, defaultConfigSyncRecompileDebounce)
	}
	if cfg.ConfigSync.RecompileBackstop != defaultConfigSyncRecompileBackstop {
		t.Errorf("ConfigSync.RecompileBackstop = %v, want %v", cfg.ConfigSync.RecompileBackstop, defaultConfigSyncRecompileBackstop)
	}
	if cfg.ConfigSync.TokenPrevious != "" {
		t.Errorf("ConfigSync.TokenPrevious default = %q, want empty", cfg.ConfigSync.TokenPrevious)
	}
}

func TestLoadConfig_DBLessDataPlaneViaEnv(t *testing.T) {
	t.Setenv("REDIS_HOST", "redis.example")
	t.Setenv("KAFKA_BROKERS", "kafka.example:9092")
	t.Setenv("CONFIG_SYNC_DATA_PLANE_ENABLED", "true")
	t.Setenv("CONFIG_SYNC_TOKEN", "config-sync-token")
	t.Setenv("CONFIG_SYNC_GRPC_ENDPOINT", "control.example:8083")
	t.Setenv("CONFIG_SYNC_LKG_KEY", aes256Key())

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig on DB-less data plane: %v", err)
	}
	if !cfg.ConfigSync.DataPlaneEnabled {
		t.Errorf("ConfigSync.DataPlaneEnabled = false, want true")
	}
	if !DBLessDataPlaneEnabled() {
		t.Errorf("DBLessDataPlaneEnabled() = false, want true")
	}
	if cfg.ConfigSync.Token != "config-sync-token" {
		t.Errorf("ConfigSync.Token = %q, want %q", cfg.ConfigSync.Token, "config-sync-token")
	}
	if cfg.ConfigSync.InstanceID == "" {
		t.Errorf("ConfigSync.InstanceID = empty, want a resolved host id")
	}
}

func TestLoadConfig_DBLessRejectsMissingConfigSyncToken(t *testing.T) {
	t.Setenv("REDIS_HOST", "redis.example")
	t.Setenv("KAFKA_BROKERS", "kafka.example:9092")
	t.Setenv("CONFIG_SYNC_DATA_PLANE_ENABLED", "true")
	t.Setenv("CONFIG_SYNC_GRPC_ENDPOINT", "control.example:8083")
	t.Setenv("CONFIG_SYNC_LKG_KEY", aes256Key())

	_, err := LoadConfig()
	if err == nil {
		t.Fatal("expected validation error when CONFIG_SYNC_TOKEN is missing on DB-less data plane")
	}
	if !stderrors.Is(err, errors.ErrInvalidConfig) {
		t.Errorf("error %v is not ErrInvalidConfig", err)
	}
}

func TestLoadConfig_ConfigSyncGRPCDefaults(t *testing.T) {
	minimumEnv(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cs := cfg.ConfigSync
	if cs.GRPCListenAddr != defaultConfigSyncGRPCListenAddr {
		t.Errorf("GRPCListenAddr = %q, want %q", cs.GRPCListenAddr, defaultConfigSyncGRPCListenAddr)
	}
	if cs.GRPCKeepaliveTime != defaultConfigSyncGRPCKeepaliveTime {
		t.Errorf("GRPCKeepaliveTime = %v, want %v", cs.GRPCKeepaliveTime, defaultConfigSyncGRPCKeepaliveTime)
	}
	if cs.GRPCKeepaliveTimeout != defaultConfigSyncGRPCKeepaliveTimeout {
		t.Errorf("GRPCKeepaliveTimeout = %v, want %v", cs.GRPCKeepaliveTimeout, defaultConfigSyncGRPCKeepaliveTimeout)
	}
	if cs.GRPCMinBackoff != defaultConfigSyncGRPCMinBackoff {
		t.Errorf("GRPCMinBackoff = %v, want %v", cs.GRPCMinBackoff, defaultConfigSyncGRPCMinBackoff)
	}
	if cs.GRPCMaxBackoff != defaultConfigSyncGRPCMaxBackoff {
		t.Errorf("GRPCMaxBackoff = %v, want %v", cs.GRPCMaxBackoff, defaultConfigSyncGRPCMaxBackoff)
	}
	if cs.OutboxRetention != defaultConfigSyncOutboxRetention {
		t.Errorf("OutboxRetention = %v, want %v", cs.OutboxRetention, defaultConfigSyncOutboxRetention)
	}
	if cs.OutboxMaxRows != defaultConfigSyncOutboxMaxRows {
		t.Errorf("OutboxMaxRows = %d, want %d", cs.OutboxMaxRows, defaultConfigSyncOutboxMaxRows)
	}
	if cs.TLSInsecure {
		t.Errorf("TLSInsecure default = true, want false")
	}
}

func TestValidate_DeployedRejectsConfigSyncTLSInsecure(t *testing.T) {
	cfg := dbLessValid()
	cfg.AppEnv = "production"
	cfg.ConfigSync.TLSInsecure = true

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for CONFIG_SYNC_TLS_INSECURE in a deployed environment")
	}
	if !stderrors.Is(err, errors.ErrInvalidConfig) {
		t.Errorf("error %v is not ErrInvalidConfig", err)
	}
}

func TestValidate_DeployedAllowsSecureConfigSync(t *testing.T) {
	cfg := dbLessValid()
	cfg.AppEnv = "production"
	cfg.ConfigSync.TLSInsecure = false

	if err := cfg.Validate(); err != nil {
		t.Fatalf("deployed data plane with TLS enabled should validate: %v", err)
	}
}

func TestValidate_LocalAllowsConfigSyncTLSInsecure(t *testing.T) {
	cfg := dbLessValid()
	cfg.AppEnv = "dev"
	cfg.ConfigSync.TLSInsecure = true

	if err := cfg.Validate(); err != nil {
		t.Fatalf("local data plane should allow CONFIG_SYNC_TLS_INSECURE: %v", err)
	}
}
