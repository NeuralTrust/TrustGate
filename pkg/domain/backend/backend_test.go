package backend

import (
	"errors"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/google/uuid"
)

func validTarget() Target {
	return Target{
		Provider:    "openai",
		Description: "primary",
		Auth:        NewAPIKeyAuth("sk-test"),
	}
}

func TestBackend_New_HappyPath(t *testing.T) {
	t.Parallel()
	gwID := uuid.New()
	b, err := New(CreateParams{
		GatewayID: gwID,
		Name:      "openai-pool",
		Algorithm: AlgorithmRoundRobin,
		Targets:   Targets{validTarget()},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.ID == uuid.Nil {
		t.Fatal("ID is zero")
	}
	if b.GatewayID != gwID {
		t.Fatalf("GatewayID = %s, want %s", b.GatewayID, gwID)
	}
	if b.Algorithm != AlgorithmRoundRobin {
		t.Fatalf("Algorithm = %q, want %q", b.Algorithm, AlgorithmRoundRobin)
	}
	if len(b.Targets) != 1 {
		t.Fatalf("Targets len = %d, want 1", len(b.Targets))
	}
	if b.Targets[0].ID == "" {
		t.Fatal("Target.ID should be auto-generated")
	}
	if b.CreatedAt.IsZero() || b.UpdatedAt.IsZero() {
		t.Fatal("timestamps are zero")
	}
}

func TestBackend_Validate_AlgorithmDefaultsToRoundRobin(t *testing.T) {
	t.Parallel()
	b := &Backend{
		ID:        uuid.New(),
		GatewayID: uuid.New(),
		Name:      "x",
		Algorithm: "",
		Targets:   Targets{validTarget()},
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.Algorithm != AlgorithmRoundRobin {
		t.Fatalf("Algorithm = %q, want %q", b.Algorithm, AlgorithmRoundRobin)
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
			mutate:  func(b *Backend) { b.GatewayID = uuid.Nil },
			wantErr: ErrInvalidGatewayID,
		},
		{
			name:    "unknown algorithm",
			mutate:  func(b *Backend) { b.Algorithm = "bogus" },
			wantErr: ErrInvalidAlgorithm,
		},
		{
			name:    "no targets",
			mutate:  func(b *Backend) { b.Targets = Targets{} },
			wantErr: ErrNoTargets,
		},
		{
			name: "semantic without embedding",
			mutate: func(b *Backend) {
				b.Algorithm = AlgorithmSemantic
				b.EmbeddingConfig = nil
			},
			wantErr: ErrInvalidEmbeddingConfig,
		},
		{
			name: "semantic target without description",
			mutate: func(b *Backend) {
				b.Algorithm = AlgorithmSemantic
				b.EmbeddingConfig = &EmbeddingConfig{
					Provider: "openai",
					Model:    "text-embedding-3-small",
					Auth:     &APIKeyAuth{APIKey: "sk-test"},
				}
				b.Targets = Targets{
					{Provider: "openai", Auth: NewAPIKeyAuth("sk-test")},
				}
			},
			wantErr: ErrInvalidTarget,
		},
		{
			name: "target without provider",
			mutate: func(b *Backend) {
				b.Targets = Targets{{Provider: "", Auth: NewAPIKeyAuth("k")}}
			},
			wantErr: ErrInvalidTarget,
		},
		{
			name: "target without auth",
			mutate: func(b *Backend) {
				b.Targets = Targets{{Provider: "openai"}}
			},
			wantErr: ErrInvalidTarget,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := &Backend{
				ID:        uuid.New(),
				GatewayID: uuid.New(),
				Name:      "x",
				Algorithm: AlgorithmRoundRobin,
				Targets:   Targets{validTarget()},
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

func TestBackend_Validate_SemanticHappyPath(t *testing.T) {
	t.Parallel()
	b := &Backend{
		ID:        uuid.New(),
		GatewayID: uuid.New(),
		Name:      "x",
		Algorithm: AlgorithmSemantic,
		EmbeddingConfig: &EmbeddingConfig{
			Provider: "openai",
			Model:    "text-embedding-3-small",
			Auth:     &APIKeyAuth{APIKey: "sk-test"},
		},
		Targets: Targets{
			{
				Provider:    "openai",
				Description: "code tasks",
				Auth:        NewAPIKeyAuth("sk-1"),
			},
			{
				Provider:    "anthropic",
				Description: "reasoning tasks",
				Auth:        NewAPIKeyAuth("sk-2"),
			},
		},
	}
	if err := b.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBackend_Rehydrate(t *testing.T) {
	t.Parallel()
	id, gwID := uuid.New(), uuid.New()
	now := time.Now().UTC()
	b := Rehydrate(id, gwID, "x", AlgorithmRandom, Targets{validTarget()}, nil, nil, now, now)
	if b.ID != id || b.GatewayID != gwID {
		t.Fatal("identity mismatch after rehydrate")
	}
	if b.Algorithm != AlgorithmRandom {
		t.Fatalf("Algorithm = %q", b.Algorithm)
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

func TestTargets_ValueAndScan(t *testing.T) {
	t.Parallel()
	original := Targets{
		{Provider: "openai", Weight: 5, Auth: NewAPIKeyAuth("sk-a")},
		{Provider: "anthropic", Weight: 1, Auth: NewAPIKeyAuth("sk-b")},
	}
	v, err := original.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	bytes, ok := v.([]byte)
	if !ok {
		t.Fatalf("Value returned %T, want []byte", v)
	}
	var roundtrip Targets
	if err := roundtrip.Scan(bytes); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(roundtrip) != len(original) {
		t.Fatalf("len = %d, want %d", len(roundtrip), len(original))
	}
	for i := range original {
		if roundtrip[i].Provider != original[i].Provider {
			t.Fatalf("Provider[%d] = %q, want %q", i, roundtrip[i].Provider, original[i].Provider)
		}
	}
}

func TestTargets_Scan_Nil(t *testing.T) {
	t.Parallel()
	var ts Targets
	if err := ts.Scan(nil); err != nil {
		t.Fatalf("Scan(nil): %v", err)
	}
	if len(ts) != 0 {
		t.Fatalf("len = %d, want 0", len(ts))
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
