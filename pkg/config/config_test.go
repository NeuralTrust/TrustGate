package config

import (
	stderrors "errors"
	"log/slog"
	"testing"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/common/errors"
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
