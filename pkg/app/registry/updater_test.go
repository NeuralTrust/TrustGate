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

package registry_test

import (
	"context"
	"errors"
	"testing"

	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func ptr[T any](v T) *T { return &v }

func TestUpdater_Update_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing, _ := domain.NewLLMRegistry(ids.New[ids.GatewayKind](), "old", "", &domain.LLMTarget{Provider: "openai", Auth: domain.NewAPIKeyAuth("sk-1")})
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
		return b.ID == existing.ID && b.Name == "new"
	})).Return(nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:       existing.ID,
		Name:     ptr("new"),
		Provider: ptr("openai"),
		Auth:     domain.NewAPIKeyAuth("sk-1"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Name != "new" {
		t.Fatalf("Name = %q, want %q", got.Name, "new")
	}
}

func TestUpdater_Update_TogglesEnabled(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing, _ := domain.NewLLMRegistry(ids.New[ids.GatewayKind](), "old", "", &domain.LLMTarget{Provider: "openai", Auth: domain.NewAPIKeyAuth("sk-1")})
	if !existing.Enabled {
		t.Fatal("precondition: freshly created registry should be enabled")
	}
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
		return b.ID == existing.ID && !b.Enabled
	})).Return(nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:      existing.ID,
		Enabled: ptr(false),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Enabled {
		t.Fatal("Enabled should be false after toggle")
	}
}

func TestUpdater_Update_EnabledUnchangedWhenNil(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing, _ := domain.NewLLMRegistry(ids.New[ids.GatewayKind](), "old", "", &domain.LLMTarget{Provider: "openai", Auth: domain.NewAPIKeyAuth("sk-1")})
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
		return b.Enabled
	})).Return(nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:   existing.ID,
		Name: ptr("renamed"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if !got.Enabled {
		t.Fatal("Enabled should remain true when not provided")
	}
}

func TestUpdater_Update_Partial_PreservesProviderOptionsAndHealthChecks(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	opts := map[string]any{"base_url": "https://example.com"}
	hc := &domain.HealthChecks{Threshold: 3, Interval: 10}
	existing, _ := domain.NewLLMRegistry(ids.New[ids.GatewayKind](), "old", "", &domain.LLMTarget{Provider: "openai", ProviderOptions: opts, Auth: domain.NewAPIKeyAuth("sk-real"), HealthChecks: hc})
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
		return b.Name == "renamed" &&
			b.ProviderOptions()["base_url"] == "https://example.com" &&
			b.HealthChecks() != nil && b.HealthChecks().Threshold == 3 &&
			b.Auth() != nil && b.Auth().APIKey != nil && b.Auth().APIKey.APIKey == "sk-real"
	})).Return(nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:   existing.ID,
		Name: ptr("renamed"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.ProviderOptions()["base_url"] != "https://example.com" {
		t.Fatalf("provider_options not preserved: %+v", got.ProviderOptions())
	}
	if got.HealthChecks() == nil || got.HealthChecks().Threshold != 3 {
		t.Fatalf("health_checks not preserved: %+v", got.HealthChecks())
	}
	if got.Auth() == nil || got.Auth().APIKey.APIKey != "sk-real" {
		t.Fatalf("auth not preserved: %+v", got.Auth())
	}
}

func TestUpdater_Update_PartialMCPTargetPreservesAuthAndHeaders(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing, err := domain.NewMCPRegistry(ids.New[ids.GatewayKind](), "mcp", "", &domain.MCPTarget{
		URL:     "https://old.example.com/mcp",
		Headers: map[string]string{"X-Tenant": "acme"},
		Auth: &domain.MCPAuth{
			Mode:         domain.MCPAuthModeForwarded,
			Provider:     "github",
			Registration: domain.RegistrationAuto,
		},
	})
	if err != nil {
		t.Fatalf("NewMCPRegistry error: %v", err)
	}
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:        existing.ID,
		MCPTarget: &domain.MCPTarget{URL: "https://new.example.com/mcp"},
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.MCPTarget.URL != "https://new.example.com/mcp" {
		t.Fatalf("URL = %q", got.MCPTarget.URL)
	}
	if got.MCPTarget.Auth == nil || got.MCPTarget.Auth.Mode != domain.MCPAuthModeForwarded || got.MCPTarget.Auth.Provider != "github" {
		t.Fatalf("forwarded auth lost on partial update: %+v", got.MCPTarget.Auth)
	}
	if got.MCPTarget.Headers["X-Tenant"] != "acme" {
		t.Fatalf("headers lost on partial update: %+v", got.MCPTarget.Headers)
	}
}

func TestUpdater_Update_MCPTargetAuthClearedExplicitly(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing, err := domain.NewMCPRegistry(ids.New[ids.GatewayKind](), "mcp", "", &domain.MCPTarget{
		URL:  "https://old.example.com/mcp",
		Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer t"},
	})
	if err != nil {
		t.Fatalf("NewMCPRegistry error: %v", err)
	}
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:        existing.ID,
		MCPTarget: &domain.MCPTarget{Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeNone}},
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.MCPTarget.URL != "https://old.example.com/mcp" {
		t.Fatalf("URL should be preserved: %q", got.MCPTarget.URL)
	}
	if got.MCPTarget.Auth.Mode != domain.MCPAuthModeNone {
		t.Fatalf("auth should be cleared: %+v", got.MCPTarget.Auth)
	}
}

func TestUpdater_Update_PreservesRedactedSecret(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing, _ := domain.NewLLMRegistry(ids.New[ids.GatewayKind](), "old", "", &domain.LLMTarget{Provider: "openai", Auth: domain.NewAPIKeyAuth("sk-real")})
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
		return b.Auth() != nil && b.Auth().APIKey != nil && b.Auth().APIKey.APIKey == "sk-real"
	})).Return(nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:       existing.ID,
		Name:     ptr("old"),
		Provider: ptr("openai"),
		Auth:     domain.NewAPIKeyAuth("***"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Auth().APIKey.APIKey != "sk-real" {
		t.Fatalf("api key = %q, want preserved sk-real", got.Auth().APIKey.APIKey)
	}
}

func TestUpdater_Update_PreservesSecretWhenAuthOmitted(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing, _ := domain.NewLLMRegistry(ids.New[ids.GatewayKind](), "old", "", &domain.LLMTarget{Provider: "openai", Auth: domain.NewAPIKeyAuth("sk-real")})
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
		return b.Name == "renamed" && b.Auth() != nil && b.Auth().APIKey.APIKey == "sk-real"
	})).Return(nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:       existing.ID,
		Name:     ptr("renamed"),
		Provider: ptr("openai"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Auth() == nil || got.Auth().APIKey.APIKey != "sk-real" {
		t.Fatalf("auth not preserved when omitted: %+v", got.Auth())
	}
}

func TestUpdater_Update_AzurePreservesAPIKeyForSameMode(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	auth := &domain.TargetAuth{
		Type: domain.AuthTypeAzure,
		Azure: &domain.AzureAuth{
			Endpoint: "https://old.openai.azure.com",
			Version:  "2024-02-15-preview",
			APIKey:   "azure-real-key",
		},
	}
	existing, _ := domain.NewLLMRegistry(ids.New[ids.GatewayKind](), "old", "", &domain.LLMTarget{Provider: "azure", Auth: auth})
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
		return b.Auth() != nil &&
			b.Auth().Azure != nil &&
			b.Auth().Azure.Endpoint == "https://new.openai.azure.com" &&
			b.Auth().Azure.APIKey == "azure-real-key" &&
			b.Auth().Azure.ClientSecret == ""
	})).Return(nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID: existing.ID,
		Auth: &domain.TargetAuth{
			Type: domain.AuthTypeAzure,
			Azure: &domain.AzureAuth{
				Endpoint: "https://new.openai.azure.com",
				Version:  "2024-02-15-preview",
				APIKey:   "***",
			},
		},
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Auth().Azure.APIKey != "azure-real-key" {
		t.Fatalf("azure api key = %q, want preserved azure-real-key", got.Auth().Azure.APIKey)
	}
}

func TestUpdater_Update_AzurePreservesClientSecretForSameServicePrincipal(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	auth := &domain.TargetAuth{
		Type: domain.AuthTypeAzure,
		Azure: &domain.AzureAuth{
			Endpoint:     "https://old.openai.azure.com",
			Version:      "2024-02-15-preview",
			ClientID:     "client-1",
			ClientSecret: "azure-real-secret",
			TenantID:     "tenant-1",
		},
	}
	existing, _ := domain.NewLLMRegistry(ids.New[ids.GatewayKind](), "old", "", &domain.LLMTarget{Provider: "azure", Auth: auth})
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
		return b.Auth() != nil &&
			b.Auth().Azure != nil &&
			b.Auth().Azure.Endpoint == "https://new.openai.azure.com" &&
			b.Auth().Azure.ClientID == "client-1" &&
			b.Auth().Azure.ClientSecret == "azure-real-secret" &&
			b.Auth().Azure.TenantID == "tenant-1"
	})).Return(nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID: existing.ID,
		Auth: &domain.TargetAuth{
			Type: domain.AuthTypeAzure,
			Azure: &domain.AzureAuth{
				Endpoint:     "https://new.openai.azure.com",
				Version:      "2024-02-15-preview",
				ClientID:     "client-1",
				ClientSecret: "***",
				TenantID:     "tenant-1",
			},
		},
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Auth().Azure.ClientSecret != "azure-real-secret" {
		t.Fatalf("azure client secret = %q, want preserved azure-real-secret", got.Auth().Azure.ClientSecret)
	}
}

func TestUpdater_Update_AzureClearsIncompatibleSecretsOnModeChange(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	auth := &domain.TargetAuth{
		Type: domain.AuthTypeAzure,
		Azure: &domain.AzureAuth{
			Endpoint:     "https://old.openai.azure.com",
			Version:      "2024-02-15-preview",
			ClientID:     "client-1",
			ClientSecret: "azure-real-secret",
			TenantID:     "tenant-1",
		},
	}
	existing, _ := domain.NewLLMRegistry(ids.New[ids.GatewayKind](), "old", "", &domain.LLMTarget{Provider: "azure", Auth: auth})
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
		return b.Auth() != nil &&
			b.Auth().Azure != nil &&
			b.Auth().Azure.APIKey == "new-api-key" &&
			b.Auth().Azure.ClientID == "" &&
			b.Auth().Azure.ClientSecret == "" &&
			b.Auth().Azure.TenantID == ""
	})).Return(nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID: existing.ID,
		Auth: &domain.TargetAuth{
			Type: domain.AuthTypeAzure,
			Azure: &domain.AzureAuth{
				Endpoint: "https://old.openai.azure.com",
				Version:  "2024-02-15-preview",
				APIKey:   "new-api-key",
			},
		},
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Auth().Azure.ClientSecret != "" {
		t.Fatalf("azure client secret = %q, want cleared on mode change", got.Auth().Azure.ClientSecret)
	}
}

func TestUpdater_Update_AzureRejectsServicePrincipalSecretForDifferentPrincipal(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	auth := &domain.TargetAuth{
		Type: domain.AuthTypeAzure,
		Azure: &domain.AzureAuth{
			Endpoint:     "https://old.openai.azure.com",
			Version:      "2024-02-15-preview",
			ClientID:     "client-1",
			ClientSecret: "azure-real-secret",
			TenantID:     "tenant-1",
		},
	}
	existing, _ := domain.NewLLMRegistry(ids.New[ids.GatewayKind](), "old", "", &domain.LLMTarget{Provider: "azure", Auth: auth})
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID: existing.ID,
		Auth: &domain.TargetAuth{
			Type: domain.AuthTypeAzure,
			Azure: &domain.AzureAuth{
				Endpoint: "https://old.openai.azure.com",
				Version:  "2024-02-15-preview",
				ClientID: "client-2",
				TenantID: "tenant-1",
			},
		},
	})
	if !errors.Is(err, domain.ErrInvalidRegistry) {
		t.Fatalf("err = %v, want ErrInvalidRegistry", err)
	}
}

func TestUpdater_Update_RejectsGatewayIDChange(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing, _ := domain.NewLLMRegistry(ids.New[ids.GatewayKind](), "x", "", &domain.LLMTarget{Provider: "openai", Auth: domain.NewAPIKeyAuth("sk-1")})
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:        existing.ID,
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      ptr("x"),
		Provider:  ptr("openai"),
		Auth:      domain.NewAPIKeyAuth("sk-1"),
	})
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestUpdater_Update_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.RegistryKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:       id,
		Name:     ptr("x"),
		Provider: ptr("openai"),
		Auth:     domain.NewAPIKeyAuth("sk-1"),
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
