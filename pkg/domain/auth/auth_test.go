package auth

import (
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/google/uuid"
)

func validAPIKeyConfig() Config {
	return Config{APIKey: &APIKeyConfig{Key: "super-secret-key"}}
}

func TestNewAuth_Defaults(t *testing.T) {
	t.Parallel()
	gwID := uuid.New()
	a, err := NewAuth(gwID, "client-key", TypeAPIKey, true, validAPIKeyConfig())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.ID == uuid.Nil {
		t.Fatal("expected generated id")
	}
	if a.GatewayID != gwID {
		t.Fatalf("expected gateway id %s, got %s", gwID, a.GatewayID)
	}
	if a.CreatedAt.IsZero() || a.UpdatedAt.IsZero() {
		t.Fatal("expected timestamps to be set")
	}
}

func TestNewAuth_Validation(t *testing.T) {
	t.Parallel()
	gwID := uuid.New()
	tests := []struct {
		name      string
		gatewayID uuid.UUID
		authName  string
		authType  Type
		config    Config
		wantErr   error
	}{
		{
			name:      "empty name",
			gatewayID: gwID,
			authName:  "  ",
			authType:  TypeAPIKey,
			config:    validAPIKeyConfig(),
			wantErr:   ErrInvalidName,
		},
		{
			name:      "nil gateway",
			gatewayID: uuid.Nil,
			authName:  "k",
			authType:  TypeAPIKey,
			config:    validAPIKeyConfig(),
			wantErr:   ErrInvalidGatewayID,
		},
		{
			name:      "invalid type",
			gatewayID: gwID,
			authName:  "k",
			authType:  Type("bogus"),
			config:    validAPIKeyConfig(),
			wantErr:   ErrInvalidType,
		},
		{
			name:      "api_key missing key",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeAPIKey,
			config:    Config{APIKey: &APIKeyConfig{}},
			wantErr:   ErrInvalidConfig,
		},
		{
			name:      "oauth2 missing issuer",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeOAuth2,
			config:    Config{OAuth2: &OAuth2Config{JWKSURL: "https://x/jwks"}},
			wantErr:   ErrInvalidConfig,
		},
		{
			name:      "oauth2 missing jwks and introspection",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeOAuth2,
			config:    Config{OAuth2: &OAuth2Config{Issuer: "https://issuer"}},
			wantErr:   ErrInvalidConfig,
		},
		{
			name:      "mtls missing ca_cert",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeMTLS,
			config:    Config{MTLS: &MTLSConfig{}},
			wantErr:   ErrInvalidConfig,
		},
		{
			name:      "config type mismatch",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeAPIKey,
			config:    Config{OAuth2: &OAuth2Config{Issuer: "https://issuer", JWKSURL: "https://x/jwks"}},
			wantErr:   ErrInvalidConfig,
		},
		{
			name:      "more than one payload",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeAPIKey,
			config:    Config{APIKey: &APIKeyConfig{Key: "k"}, MTLS: &MTLSConfig{CACert: "pem"}},
			wantErr:   ErrInvalidConfig,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewAuth(tt.gatewayID, tt.authName, tt.authType, true, tt.config)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
			if !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("expected validation error wrapping, got %v", err)
			}
		})
	}
}

func TestNewAuth_ValidPerType(t *testing.T) {
	t.Parallel()
	gwID := uuid.New()
	cases := map[string]struct {
		authType Type
		config   Config
	}{
		"api_key": {TypeAPIKey, validAPIKeyConfig()},
		"oauth2": {TypeOAuth2, Config{OAuth2: &OAuth2Config{
			Issuer:  "https://issuer",
			JWKSURL: "https://issuer/.well-known/jwks.json",
		}}},
		"mtls": {TypeMTLS, Config{MTLS: &MTLSConfig{CACert: "-----BEGIN CERTIFICATE-----"}}},
	}
	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewAuth(gwID, name, tc.authType, true, tc.config); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestConfig_ScanNil(t *testing.T) {
	t.Parallel()
	var c Config
	if err := c.Scan(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.APIKey != nil || c.OAuth2 != nil || c.MTLS != nil {
		t.Fatal("expected empty config after scanning nil")
	}
}

func TestConfig_ValueRoundTrip(t *testing.T) {
	t.Parallel()
	original := validAPIKeyConfig()
	v, err := original.Value()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw, ok := v.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", v)
	}
	var got Config
	if err := got.Scan(raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.APIKey == nil || got.APIKey.Key != original.APIKey.Key {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}
