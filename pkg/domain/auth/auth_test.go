package auth

import (
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/common/secret"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

func TestConfig_Validate_RejectsRedactedClientSecret(t *testing.T) {
	t.Parallel()
	cfg := Config{OAuth2: &OAuth2Config{
		Issuer:       "https://issuer.example.com",
		Audiences:    []string{"gateway"},
		JWKSURL:      "https://issuer.example.com/jwks",
		ClientSecret: secret.Redacted,
	}}
	if err := cfg.Validate(TypeOAuth2); err == nil {
		t.Fatal("Validate() = nil, want rejection of redaction placeholder")
	}
}

func TestConfig_ResolveSecretsFrom_KeepsOAuth2Secret(t *testing.T) {
	t.Parallel()
	prev := Config{OAuth2: &OAuth2Config{
		Issuer:       "https://issuer.example.com",
		Audiences:    []string{"gateway"},
		JWKSURL:      "https://issuer.example.com/jwks",
		ClientSecret: "stored-secret",
	}}
	next := Config{OAuth2: &OAuth2Config{
		Issuer:       "https://issuer.example.com",
		Audiences:    []string{"gateway"},
		JWKSURL:      "https://issuer.example.com/jwks",
		ClientSecret: secret.Mask("stored-secret"),
	}}
	next.ResolveSecretsFrom(prev)
	if next.OAuth2.ClientSecret != "stored-secret" {
		t.Fatalf("ClientSecret = %q, want stored value kept", next.OAuth2.ClientSecret)
	}
}

func TestNewAPIKeyAuth_GeneratesKey(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	a, err := NewAPIKeyAuth(gwID, "client-key", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.ID.IsNil() {
		t.Fatal("expected generated id")
	}
	if a.GatewayID != gwID {
		t.Fatalf("expected gateway id %s, got %s", gwID, a.GatewayID)
	}
	if a.Type != TypeAPIKey {
		t.Fatalf("expected api_key type, got %s", a.Type)
	}
	if a.RawKey == "" {
		t.Fatal("expected a generated plaintext key")
	}
	if a.KeyHash != HashAPIKey(a.RawKey) {
		t.Fatal("KeyHash must be the hash of RawKey")
	}
	if a.CreatedAt.IsZero() || a.UpdatedAt.IsZero() {
		t.Fatal("expected timestamps to be set")
	}
}

func TestNewAPIKeyAuth_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	_, err := NewAPIKeyAuth(ids.New[ids.GatewayKind](), "  ", true)
	if !errors.Is(err, ErrInvalidName) {
		t.Fatalf("err = %v, want ErrInvalidName", err)
	}
}

func TestGenerateAPIKey_UniqueAndPrefixed(t *testing.T) {
	t.Parallel()
	k1, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	k2, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if k1 == k2 {
		t.Fatal("two generated keys must differ")
	}
	if len(k1) < len(apiKeyPrefix)+10 || k1[:len(apiKeyPrefix)] != apiKeyPrefix {
		t.Fatalf("generated key %q must carry the %q prefix", k1, apiKeyPrefix)
	}
}

func TestHashAPIKey_Deterministic(t *testing.T) {
	t.Parallel()
	h1 := HashAPIKey("ag_secret")
	h2 := HashAPIKey("ag_secret")
	if h1 != h2 {
		t.Fatal("hash must be deterministic")
	}
	if HashAPIKey("ag_a") == HashAPIKey("ag_b") {
		t.Fatal("different keys must hash differently")
	}
}

func TestNewAuth_Validation(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	tests := []struct {
		name      string
		gatewayID ids.GatewayID
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
			config:    Config{},
			wantErr:   ErrInvalidName,
		},
		{
			name:      "nil gateway",
			gatewayID: ids.GatewayID{},
			authName:  "k",
			authType:  TypeAPIKey,
			config:    Config{},
			wantErr:   ErrInvalidGatewayID,
		},
		{
			name:      "invalid type",
			gatewayID: gwID,
			authName:  "k",
			authType:  Type("bogus"),
			config:    Config{},
			wantErr:   ErrInvalidType,
		},
		{
			name:      "api_key must not carry a config payload",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeAPIKey,
			config:    Config{OAuth2: &OAuth2Config{Issuer: "https://issuer", JWKSURL: "https://x/jwks"}},
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
			name:      "oauth2 missing jwks and introspection with non-URL issuer",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeOAuth2,
			config:    Config{OAuth2: &OAuth2Config{Issuer: "not-a-url", Audiences: []string{"gateway"}}},
			wantErr:   ErrInvalidConfig,
		},
		{
			name:      "oauth2 missing audiences",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeOAuth2,
			config:    Config{OAuth2: &OAuth2Config{Issuer: "https://issuer", JWKSURL: "https://x/jwks"}},
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
			name:      "idp missing key material",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeIDP,
			config:    Config{IDP: &IDPConfig{Issuer: "https://issuer", Audiences: []string{"gateway"}}},
			wantErr:   ErrInvalidConfig,
		},
		{
			name:      "idp rejects hs algorithms",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeIDP,
			config: Config{IDP: &IDPConfig{
				Issuer:            "https://issuer",
				Audiences:         []string{"gateway"},
				JWKSURL:           "https://issuer/.well-known/jwks.json",
				AllowedAlgorithms: []string{"HS256"},
			}},
			wantErr: ErrInvalidConfig,
		},
		{
			name:      "oauth2 with extra mtls payload",
			gatewayID: gwID,
			authName:  "k",
			authType:  TypeOAuth2,
			config:    Config{OAuth2: &OAuth2Config{Issuer: "https://issuer", JWKSURL: "https://x/jwks"}, MTLS: &MTLSConfig{CACert: "pem"}},
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
	gwID := ids.New[ids.GatewayKind]()
	cases := map[string]struct {
		authType Type
		config   Config
	}{
		"api_key": {TypeAPIKey, Config{}},
		"oauth2": {TypeOAuth2, Config{OAuth2: &OAuth2Config{
			Issuer:    "https://issuer",
			Audiences: []string{"gateway"},
			JWKSURL:   "https://issuer/.well-known/jwks.json",
		}}},
		"oauth2 issuer-only (JWKS via OIDC discovery)": {TypeOAuth2, Config{OAuth2: &OAuth2Config{
			Issuer:    "https://login.microsoftonline.com/tenant-id/v2.0",
			Audiences: []string{"agentgateway"},
		}}},
		"mtls": {TypeMTLS, Config{MTLS: &MTLSConfig{CACert: "-----BEGIN CERTIFICATE-----"}}},
		"idp": {TypeIDP, Config{IDP: &IDPConfig{
			Issuer:            "https://issuer",
			Audiences:         []string{"gateway"},
			JWKSURL:           "https://issuer/.well-known/jwks.json",
			AllowedAlgorithms: []string{"RS256"},
		}}},
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
	if c.OAuth2 != nil || c.IDP != nil || c.MTLS != nil {
		t.Fatal("expected empty config after scanning nil")
	}
}

func TestConfig_ValueRoundTrip(t *testing.T) {
	t.Parallel()
	original := Config{OAuth2: &OAuth2Config{
		Issuer:    "https://issuer",
		Audiences: []string{"gateway"},
		JWKSURL:   "https://issuer/.well-known/jwks.json",
	}}
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
	if got.OAuth2 == nil || got.OAuth2.Issuer != original.OAuth2.Issuer {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}
