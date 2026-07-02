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
	"io"
	"log/slog"
	"testing"
	"time"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/mock"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCacheManager() *cache.TTLMapManager {
	return cache.NewTTLMapManager(time.Hour)
}

func validCreateInput(gwID ids.GatewayID, name string) appregistry.CreateInput {
	return appregistry.CreateInput{
		GatewayID: gwID,
		Name:      name,
		LLMTarget: &domain.LLMTarget{
			Provider: "openai",
			Auth:     domain.NewAPIKeyAuth("sk-1"),
		},
	}
}

func TestCreator_Create_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
			return b.GatewayID == gwID && b.Name == "backend-1" && b.Provider() == "openai"
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := appregistry.NewCreator(repo, mgr, newTestLogger(), nil)

	b, err := creator.Create(context.Background(), validCreateInput(gwID, "backend-1"))
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	cached, ok := mgr.GetTTLMap(cache.RegistryTTLName).Get(b.ID.String())
	if !ok {
		t.Fatal("created backend was not pre-warmed in the cache")
	}
	if cached.(*domain.Registry).ID != b.ID {
		t.Fatal("cached backend ID mismatch")
	}
}

func TestCreator_Create_EnabledFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		enabled bool
	}{
		{name: "enabled", enabled: true},
		{name: "disabled", enabled: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			repo := repomocks.NewRepository(t)
			gwID := ids.New[ids.GatewayKind]()
			repo.EXPECT().
				Save(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
					return b.Enabled == tt.enabled
				})).
				Return(nil).
				Once()

			creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil)
			in := validCreateInput(gwID, "backend-"+tt.name)
			in.Enabled = ptr(tt.enabled)
			got, err := creator.Create(context.Background(), in)
			if err != nil {
				t.Fatalf("Create error: %v", err)
			}
			if got.Enabled != tt.enabled {
				t.Fatalf("Enabled = %v, want %v", got.Enabled, tt.enabled)
			}
		})
	}
}

func TestCreator_Create_EnabledDefaultsTrueWhenNil(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
			return b.Enabled
		})).
		Return(nil).
		Once()

	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil)
	in := validCreateInput(gwID, "backend-default")
	if in.Enabled != nil {
		t.Fatal("precondition: Enabled should be unset in validCreateInput")
	}
	got, err := creator.Create(context.Background(), in)
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if !got.Enabled {
		t.Fatal("Enabled should default to true when not provided")
	}
}

func TestCreator_Create_AzureModes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		auth *domain.TargetAuth
		want providers.Azure
		key  string
	}{
		{
			name: "api key",
			auth: &domain.TargetAuth{
				Type:  domain.AuthTypeAzure,
				Azure: &domain.AzureAuth{Endpoint: "https://example.openai.azure.com", APIKey: "azure-key"},
			},
			want: providers.Azure{
				Endpoint: "https://example.openai.azure.com",
				AuthMode: providers.AzureAuthModeAPIKey,
			},
			key: "azure-key",
		},
		{
			name: "service principal",
			auth: &domain.TargetAuth{
				Type: domain.AuthTypeAzure,
				Azure: &domain.AzureAuth{
					Endpoint:     "https://example.openai.azure.com",
					ClientID:     "client",
					ClientSecret: "secret",
					TenantID:     "tenant",
				},
			},
			want: providers.Azure{
				Endpoint:     "https://example.openai.azure.com",
				AuthMode:     providers.AzureAuthModeServicePrincipal,
				ClientID:     "client",
				ClientSecret: "secret",
				TenantID:     "tenant",
			},
		},
		{
			name: "default azure credential",
			auth: &domain.TargetAuth{
				Type:  domain.AuthTypeAzure,
				Azure: &domain.AzureAuth{Endpoint: "https://example.openai.azure.com", UseManagedIdentity: true},
			},
			want: providers.Azure{
				Endpoint:    "https://example.openai.azure.com",
				AuthMode:    providers.AzureAuthModeDefaultAzureCredential,
				UseIdentity: true,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			repo := repomocks.NewRepository(t)
			gwID := ids.New[ids.GatewayKind]()
			repo.EXPECT().
				Save(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
					creds := b.Auth().ProviderCredentials()
					return b.GatewayID == gwID &&
						b.Provider() == "azure" &&
						creds.ApiKey == tt.key &&
						creds.Azure != nil &&
						*creds.Azure == tt.want
				})).
				Return(nil).
				Once()

			creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil)
			got, err := creator.Create(context.Background(), appregistry.CreateInput{
				GatewayID: gwID,
				Name:      "azure-" + tt.name,
				LLMTarget: &domain.LLMTarget{Provider: "azure", Auth: tt.auth},
			})

			if err != nil {
				t.Fatalf("Create error: %v", err)
			}
			if got.Provider() != "azure" {
				t.Fatalf("Provider = %q, want azure", got.Provider())
			}
		})
	}
}

func TestCreator_Create_RejectsInvalid(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil)

	in := validCreateInput(ids.New[ids.GatewayKind](), "x")
	in.LLMTarget.Provider = ""
	_, err := creator.Create(context.Background(), in)
	if !errors.Is(err, domain.ErrInvalidRegistry) {
		t.Fatalf("err = %v, want ErrInvalidRegistry", err)
	}
}

func TestCreator_Create_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(domain.ErrAlreadyExists).Once()
	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil)

	_, err := creator.Create(context.Background(), validCreateInput(ids.New[ids.GatewayKind](), "dupe"))
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}
