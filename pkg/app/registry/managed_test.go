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

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

func managedCreateInput(gwID ids.GatewayID) appregistry.CreateInput {
	return appregistry.CreateInput{
		GatewayID: gwID,
		Name:      "OpenAI (NeuralTrust)",
		Type:      domain.TypeLLM,
		LLMTarget: &domain.LLMTarget{Provider: "openai"},
		Managed:   true,
	}
}

func managedRegistry(t *testing.T) *domain.Registry {
	t.Helper()
	reg, err := domain.NewManagedLLMRegistry(ids.New[ids.GatewayKind](), "OpenAI (NeuralTrust)", "", &domain.LLMTarget{Provider: "openai"})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestCreator_Managed_PlatformOnly(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()

	t.Run("tenant", func(t *testing.T) {
		t.Parallel()
		creator := appregistry.NewCreator(repomocks.NewRepository(t), newCacheManager(), newTestLogger(), nil, nil)
		if _, err := creator.Create(context.Background(), managedCreateInput(gwID)); !errors.Is(err, domain.ErrManaged) {
			t.Fatalf("err = %v, want ErrManaged", err)
		}
	})

	t.Run("platform", func(t *testing.T) {
		t.Parallel()
		repo := repomocks.NewRepository(t)
		repo.EXPECT().Save(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
			return b.Managed && b.Auth() == nil && b.Provider() == "openai"
		})).Return(nil).Once()
		creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil, nil)
		reg, err := creator.Create(appregistry.AsPlatform(context.Background()), managedCreateInput(gwID))
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if !reg.Managed {
			t.Fatal("created registry is not managed")
		}
	})

	t.Run("not an LLM registry", func(t *testing.T) {
		t.Parallel()
		creator := appregistry.NewCreator(repomocks.NewRepository(t), newCacheManager(), newTestLogger(), nil, nil)
		in := managedCreateInput(gwID)
		in.Type = domain.TypeMCP
		if _, err := creator.Create(appregistry.AsPlatform(context.Background()), in); !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("err = %v, want a validation error", err)
		}
	})
}

func TestUpdater_Managed_RefusesTenant(t *testing.T) {
	t.Parallel()
	existing := managedRegistry(t)
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil, nil)
	_, err := updater.Update(context.Background(), appregistry.UpdateInput{
		ID:              existing.ID,
		ProviderOptions: &map[string]any{"base_url": "https://evil.example"},
	})
	if !errors.Is(err, domain.ErrManaged) || !errors.Is(err, commonerrors.ErrForbidden) {
		t.Fatalf("err = %v, want ErrManaged (forbidden)", err)
	}
}

func TestUpdater_Managed_PlatformMayRename(t *testing.T) {
	t.Parallel()
	existing := managedRegistry(t)
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(b *domain.Registry) bool {
		return b.Managed && b.Name == "OpenAI"
	})).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateRegistryCacheEvent{GatewayID: existing.GatewayID.String(), RegistryID: existing.ID.String()}).
		Return(nil).
		Once()

	updater := appregistry.NewUpdater(repo, newCacheManager(), publisher, newTestLogger(), nil, nil)
	name := "OpenAI"
	if _, err := updater.Update(appregistry.AsPlatform(context.Background()), appregistry.UpdateInput{ID: existing.ID, Name: &name}); err != nil {
		t.Fatalf("Update: %v", err)
	}
}

func TestDeleter_Managed_RefusesTenant(t *testing.T) {
	t.Parallel()
	existing := managedRegistry(t)
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	deleter := appregistry.NewDeleter(repo, newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil)
	if err := deleter.Delete(context.Background(), existing.GatewayID, existing.ID); !errors.Is(err, domain.ErrManaged) {
		t.Fatalf("err = %v, want ErrManaged", err)
	}
}
