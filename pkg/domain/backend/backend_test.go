package backend

import (
	"errors"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

func TestBackend_New_HappyPath(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	b, err := NewBackend(gwID, "openai-1", "openai", nil, "primary", 5, NewAPIKeyAuth("sk-test"), nil)
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
		mutate  func(*Backend)
		wantErr error
	}{
		{
			name:    "empty name",
			mutate:  func(b *Backend) { b.Name = "" },
			wantErr: commonerrors.ErrValidation,
		},
		{
			name:    "nil gateway id",
			mutate:  func(b *Backend) { b.GatewayID = ids.GatewayID{} },
			wantErr: ErrInvalidGatewayID,
		},
		{
			name:    "negative weight",
			mutate:  func(b *Backend) { b.Weight = -1 },
			wantErr: ErrInvalidBackend,
		},
		{
			name:    "no provider",
			mutate:  func(b *Backend) { b.Provider = "" },
			wantErr: ErrInvalidBackend,
		},
		{
			name:    "no auth",
			mutate:  func(b *Backend) { b.Auth = nil },
			wantErr: ErrInvalidBackend,
		},
		{
			name:    "invalid auth",
			mutate:  func(b *Backend) { b.Auth = &TargetAuth{Type: AuthTypeAPIKey} },
			wantErr: ErrInvalidBackend,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := &Backend{
				ID:        ids.New[ids.BackendKind](),
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

func TestBackend_Rehydrate(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.BackendKind]()
	gwID := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	b := Rehydrate(id, gwID, "x", "anthropic", map[string]any{"k": "v"}, "desc", 3, NewAPIKeyAuth("sk-1"), nil, now, now)
	if b.ID != id || b.GatewayID != gwID {
		t.Fatal("identity mismatch after rehydrate")
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
		{name: "azure ok", auth: &TargetAuth{Type: AuthTypeAzure, Azure: &AzureAuth{Endpoint: "https://x"}}},
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
