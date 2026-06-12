package registry

import (
	"errors"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
)

func TestBackend_New_HappyPath(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	b, err := NewRegistry(gwID, "openai-1", "openai", nil, "primary", 5, NewAPIKeyAuth("sk-test"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.ID.IsNil() {
		t.Fatal("ID is zero")
	}
	if b.GatewayID != gwID {
		t.Fatalf("GatewayID = %s, want %s", b.GatewayID, gwID)
	}
	if b.Provider != "openai" {
		t.Fatalf("Provider = %q, want openai", b.Provider)
	}
	if b.Weight != 5 {
		t.Fatalf("Weight = %d, want 5", b.Weight)
	}
	if b.CreatedAt.IsZero() || b.UpdatedAt.IsZero() {
		t.Fatal("timestamps are zero")
	}
}

func TestBackend_Validate_Rejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*Registry)
		wantErr error
	}{
		{
			name:    "empty name",
			mutate:  func(b *Registry) { b.Name = "" },
			wantErr: commonerrors.ErrValidation,
		},
		{
			name:    "nil gateway id",
			mutate:  func(b *Registry) { b.GatewayID = ids.GatewayID{} },
			wantErr: ErrInvalidGatewayID,
		},
		{
			name:    "negative weight",
			mutate:  func(b *Registry) { b.Weight = -1 },
			wantErr: ErrInvalidRegistry,
		},
		{
			name:    "no provider",
			mutate:  func(b *Registry) { b.Provider = "" },
			wantErr: ErrInvalidRegistry,
		},
		{
			name:    "no auth",
			mutate:  func(b *Registry) { b.Auth = nil },
			wantErr: ErrInvalidRegistry,
		},
		{
			name:    "invalid auth",
			mutate:  func(b *Registry) { b.Auth = &TargetAuth{Type: AuthTypeAPIKey} },
			wantErr: ErrInvalidRegistry,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := &Registry{
				ID:        ids.New[ids.RegistryKind](),
				GatewayID: ids.New[ids.GatewayKind](),
				Name:      "x",
				Provider:  "openai",
				Auth:      NewAPIKeyAuth("sk-test"),
			}
			tc.mutate(b)
			err := b.Validate()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want wrap of %v", err, tc.wantErr)
			}
		})
	}
}

func TestBackend_Validate_OpenAICompatible(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()

	t.Run("missing base_url is rejected", func(t *testing.T) {
		t.Parallel()
		_, err := NewRegistry(gwID, "compat-1", "openai_compatible", nil, "", 1, NewAPIKeyAuth("sk-test"), nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, ErrInvalidRegistry) {
			t.Fatalf("err = %v, want wrap of ErrInvalidRegistry", err)
		}
	})

	t.Run("with base_url is accepted", func(t *testing.T) {
		t.Parallel()
		b, err := NewRegistry(gwID, "compat-2", "openai_compatible",
			map[string]any{"base_url": "https://api.together.xyz/v1"}, "", 1, NewAPIKeyAuth("sk-test"), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if b.Provider != "openai_compatible" {
			t.Fatalf("Provider = %q, want openai_compatible", b.Provider)
		}
	})
}

func TestBackend_Rehydrate(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.RegistryKind]()
	gwID := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	b := Rehydrate(RehydrateParams{
		ID:              id,
		GatewayID:       gwID,
		Name:            "x",
		Provider:        "anthropic",
		ProviderOptions: map[string]any{"k": "v"},
		Description:     "desc",
		Weight:          3,
		Auth:            NewAPIKeyAuth("sk-1"),
		CreatedAt:       now,
		UpdatedAt:       now,
	})
	if b.ID != id || b.GatewayID != gwID {
		t.Fatal("identity mismatch after rehydrate")
	}
	if b.Type != TypeLLM {
		t.Fatalf("Type = %q, want %q (default for legacy rows)", b.Type, TypeLLM)
	}
	if b.Provider != "anthropic" {
		t.Fatalf("Provider = %q", b.Provider)
	}
	if b.Weight != 3 {
		t.Fatalf("Weight = %d, want 3", b.Weight)
	}
	if !b.CreatedAt.Equal(now) {
		t.Fatal("CreatedAt mismatch")
	}
}

func TestBackend_Rehydrate_MCP(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.RegistryKind]()
	gwID := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	target := &MCPTarget{
		URL:  "https://mcp.example.com/mcp",
		Auth: &MCPAuth{Mode: MCPAuthModeNone},
	}
	b := Rehydrate(RehydrateParams{
		ID:        id,
		GatewayID: gwID,
		Name:      "github",
		Type:      TypeMCP,
		MCPTarget: target,
		CreatedAt: now,
		UpdatedAt: now,
	})
	// Regression: Type and MCPTarget must round-trip through Rehydrate;
	// dropping them coerced MCP registries into corrupt LLM ones.
	if b.Type != TypeMCP {
		t.Fatalf("Type = %q, want %q", b.Type, TypeMCP)
	}
	if b.MCPTarget == nil || b.MCPTarget.URL != "https://mcp.example.com/mcp" {
		t.Fatalf("MCPTarget lost on rehydrate: %+v", b.MCPTarget)
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("rehydrated MCP registry should validate: %v", err)
	}
}

func TestTargetAuth_Validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		auth    *TargetAuth
		wantErr bool
	}{
		{name: "api_key ok", auth: NewAPIKeyAuth("sk-1")},
		{name: "api_key missing payload", auth: &TargetAuth{Type: AuthTypeAPIKey}, wantErr: true},
		{name: "api_key empty fields", auth: &TargetAuth{Type: AuthTypeAPIKey, APIKey: &APIKeyAuth{}}, wantErr: true},
		{name: "azure ok with api key", auth: &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{Endpoint: "https://x", APIKey: "az-key"}}},
		{name: "azure ok with service principal", auth: &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{Endpoint: "https://x", ClientID: "client", ClientSecret: "secret", TenantID: "tenant"}}},
		{name: "azure ok with managed identity", auth: &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{Endpoint: "https://x", UseManagedIdentity: true}}},
		{name: "azure missing key and identity", auth: &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{Endpoint: "https://x"}}, wantErr: true},
		{name: "azure missing endpoint", auth: &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{APIKey: "az-key"}}, wantErr: true},
		{name: "azure incomplete service principal", auth: &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{Endpoint: "https://x", ClientID: "client", ClientSecret: "secret"}}, wantErr: true},
		{name: "azure client id only", auth: &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{Endpoint: "https://x", ClientID: "client"}}, wantErr: true},
		{name: "azure tenant id only", auth: &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{Endpoint: "https://x", TenantID: "tenant"}}, wantErr: true},
		{name: "azure client secret only", auth: &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{Endpoint: "https://x", ClientSecret: "secret"}}, wantErr: true},
		{name: "azure api key mixed with service principal", auth: &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{Endpoint: "https://x", APIKey: "az-key", ClientID: "client", ClientSecret: "secret", TenantID: "tenant"}}, wantErr: true},
		{name: "azure api key mixed with managed identity", auth: &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{Endpoint: "https://x", APIKey: "az-key", UseManagedIdentity: true}}, wantErr: true},
		{name: "azure service principal mixed with managed identity", auth: &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{Endpoint: "https://x", ClientID: "client", ClientSecret: "secret", TenantID: "tenant", UseManagedIdentity: true}}, wantErr: true},
		{name: "azure nil payload", auth: &TargetAuth{Type: AuthTypeAzure}, wantErr: true},
		{name: "aws ok", auth: &TargetAuth{Type: AuthTypeAWS, AWS: &AWSAuth{Region: "us-east-1"}}},
		{name: "aws nil payload", auth: &TargetAuth{Type: AuthTypeAWS}, wantErr: true},
		{name: "oauth2 ok", auth: NewOAuth2Auth(&TargetOAuthConfig{TokenURL: "https://x", GrantType: "client_credentials"})},
		{name: "oauth2 missing token_url", auth: NewOAuth2Auth(&TargetOAuthConfig{GrantType: "client_credentials"}), wantErr: true},
		{name: "oauth2 missing grant_type", auth: NewOAuth2Auth(&TargetOAuthConfig{TokenURL: "https://x"}), wantErr: true},
		{name: "oauth2 nil config", auth: &TargetAuth{Type: AuthTypeOAuth2}, wantErr: true},
		{name: "gcp ok", auth: NewGCPServiceAccountAuth("eyJ...")},
		{name: "gcp empty", auth: &TargetAuth{Type: AuthTypeGCPServiceAccount}, wantErr: true},
		{name: "unknown type", auth: &TargetAuth{Type: "weird"}, wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.auth.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestAzureAuth_CredentialMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		auth    *AzureAuth
		want    AzureCredentialMode
		wantErr bool
	}{
		{name: "api key", auth: &AzureAuth{Endpoint: "https://x", APIKey: "az-key"}, want: AzureCredentialModeAPIKey},
		{name: "service principal", auth: &AzureAuth{Endpoint: "https://x", ClientID: "client", ClientSecret: "secret", TenantID: "tenant"}, want: AzureCredentialModeServicePrincipal},
		{name: "default azure credential", auth: &AzureAuth{Endpoint: "https://x", UseManagedIdentity: true}, want: AzureCredentialModeDefaultAzureCredential},
		{name: "mixed modes", auth: &AzureAuth{Endpoint: "https://x", APIKey: "az-key", UseManagedIdentity: true}, wantErr: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.auth.CredentialMode()
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.wantErr && got != tc.want {
				t.Fatalf("CredentialMode() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTargetAuth_ProviderCredentials_Azure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		auth      *TargetAuth
		wantKey   string
		wantAzure providers.Azure
	}{
		{
			name:    "api key",
			auth:    &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{Endpoint: "https://x", Version: "2025-01-01", APIKey: "az-key"}},
			wantKey: "az-key",
			wantAzure: providers.Azure{
				Endpoint:   "https://x",
				ApiVersion: "2025-01-01",
				AuthMode:   providers.AzureAuthModeAPIKey,
			},
		},
		{
			name: "service principal",
			auth: &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{
				Endpoint:     "https://x",
				Version:      "2025-01-01",
				ClientID:     "client",
				ClientSecret: "secret",
				TenantID:     "tenant",
			}},
			wantAzure: providers.Azure{
				Endpoint:     "https://x",
				ApiVersion:   "2025-01-01",
				AuthMode:     providers.AzureAuthModeServicePrincipal,
				ClientID:     "client",
				ClientSecret: "secret",
				TenantID:     "tenant",
			},
		},
		{
			name: "default azure credential",
			auth: &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{
				Endpoint:           "https://x",
				Version:            "2025-01-01",
				UseManagedIdentity: true,
			}},
			wantAzure: providers.Azure{
				Endpoint:    "https://x",
				ApiVersion:  "2025-01-01",
				AuthMode:    providers.AzureAuthModeDefaultAzureCredential,
				UseIdentity: true,
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			creds := tc.auth.ProviderCredentials()
			if creds.ApiKey != tc.wantKey {
				t.Fatalf("ApiKey = %q, want %q", creds.ApiKey, tc.wantKey)
			}
			if creds.Azure == nil {
				t.Fatal("Azure credentials are nil")
			}
			if *creds.Azure != tc.wantAzure {
				t.Fatalf("Azure credentials = %+v, want %+v", *creds.Azure, tc.wantAzure)
			}
		})
	}
}

func TestRegistry_Rehydrate_AllowsLegacyAzureWithoutEndpoint(t *testing.T) {
	t.Parallel()

	auth := &TargetAuth{
		Type:  AuthTypeAzure,
		Azure: &AzureAuth{APIKey: "legacy-key"},
	}
	got := Rehydrate(RehydrateParams{
		ID:        ids.New[ids.RegistryKind](),
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "legacy-azure",
		Provider:  "azure",
		Weight:    1,
		Auth:      auth,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	if got.Auth == nil || got.Auth.Azure == nil {
		t.Fatalf("legacy Azure auth not rehydrated: %+v", got.Auth)
	}
	if got.Auth.Azure.APIKey != "legacy-key" {
		t.Fatalf("legacy Azure APIKey = %q, want legacy-key", got.Auth.Azure.APIKey)
	}
	if err := got.Validate(); err == nil {
		t.Fatal("Validate() = nil, want writes to reject missing azure.endpoint")
	}
}

func TestEmbeddingConfig_ValueAndScan(t *testing.T) {
	t.Parallel()
	original := &EmbeddingConfig{
		Provider: "openai",
		Model:    "text-embedding-3-small",
		Auth:     &APIKeyAuth{APIKey: "sk-e"},
	}
	v, err := original.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	bytes, ok := v.([]byte)
	if !ok {
		t.Fatalf("Value returned %T, want []byte", v)
	}
	var rt EmbeddingConfig
	if err := rt.Scan(bytes); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rt.Provider != original.Provider || rt.Model != original.Model {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", rt, original)
	}
}
