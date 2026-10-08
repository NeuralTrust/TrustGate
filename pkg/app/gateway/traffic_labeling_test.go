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

package gateway_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	registrymocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func classifierRegistry(gatewayID ids.GatewayID) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		GatewayID: gatewayID,
		Name:      "classifier",
		Type:      registrydomain.TypeLLM,
		LLMTarget: &registrydomain.LLMTarget{Provider: "openai", Auth: registrydomain.NewAPIKeyAuth("sk-stored")},
	}
}

func labelingFor(reg *registrydomain.Registry) *trafficlabel.Config {
	return &trafficlabel.Config{Enabled: true, RegistryID: " " + reg.ID.String() + " ", Model: " gpt-4o-mini "}
}

func updateWithRegistry(t *testing.T, mutate func(id ids.GatewayID, reg *registrydomain.Registry), findErr error) (*domain.Gateway, error) {
	t.Helper()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "gw", "active", "", nil, nil, nil, now, now)
	reg := classifierRegistry(id)
	if mutate != nil {
		mutate(id, reg)
	}

	registries := registrymocks.NewRepository(t)
	if findErr != nil {
		registries.EXPECT().FindByID(mock.Anything, reg.ID).Return(nil, findErr).Once()
	} else {
		registries.EXPECT().FindByID(mock.Anything, reg.ID).Return(reg, nil).Once()
	}
	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Maybe()
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Maybe()

	updater := appgateway.NewUpdater(repo, registries, newCacheManager(), publisher, nil, newTestLogger(), nil, false, nil)
	return updater.Update(context.Background(), appgateway.UpdateInput{ID: id, TrafficLabeling: labelingFor(reg)})
}

func TestUpdater_Update_TrafficLabeling_StoresNormalizedConfig(t *testing.T) {
	t.Parallel()
	got, err := updateWithRegistry(t, nil, nil)
	require.NoError(t, err)
	tl := got.TrafficLabeling
	require.NotNil(t, tl)
	assert.True(t, tl.IsEnabled())
	assert.Equal(t, "gpt-4o-mini", tl.Model)
	assert.Equal(t, trafficlabel.DefaultMessageWindow, tl.MessageWindow)
	require.NotNil(t, tl.SamplingRate)
	assert.InDelta(t, 1.0, *tl.SamplingRate, 1e-9)
}

func TestUpdater_Update_TrafficLabeling_RegistryChecks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(id ids.GatewayID, reg *registrydomain.Registry)
		findErr error
	}{
		{name: "registry does not exist", findErr: registrydomain.ErrNotFound},
		{name: "registry of another gateway", mutate: func(_ ids.GatewayID, reg *registrydomain.Registry) {
			reg.GatewayID = ids.New[ids.GatewayKind]()
		}},
		{name: "MCP registry", mutate: func(_ ids.GatewayID, reg *registrydomain.Registry) {
			reg.Type = registrydomain.TypeMCP
		}},
		{name: "client pass-through auth", mutate: func(_ ids.GatewayID, reg *registrydomain.Registry) {
			reg.LLMTarget.Auth = &registrydomain.TargetAuth{Type: registrydomain.AuthTypePassthrough}
		}},
		{name: "oauth2 auth", mutate: func(_ ids.GatewayID, reg *registrydomain.Registry) {
			reg.LLMTarget.Auth = &registrydomain.TargetAuth{Type: registrydomain.AuthTypeOAuth2}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := updateWithRegistry(t, tt.mutate, tt.findErr)
			require.Error(t, err)
			assert.True(t, errors.Is(err, commonerrors.ErrValidation), "error %v must be a validation error", err)
			assert.ErrorIs(t, err, appgateway.ErrInvalidTrafficLabelingRegistry)
		})
	}
}

func TestUpdater_Update_TrafficLabeling_LookupFailureIsNotAValidationError(t *testing.T) {
	t.Parallel()
	_, err := updateWithRegistry(t, nil, errors.New("connection refused"))
	require.Error(t, err)
	assert.False(t, errors.Is(err, commonerrors.ErrValidation))
}

func TestUpdater_Update_TrafficLabeling_DisabledSkipsTheRegistry(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(id, "gw", "active", "", nil, nil, nil, now, now)
	repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
			return g.TrafficLabeling != nil && !g.TrafficLabeling.Enabled
		})).
		Return(nil).
		Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()

	updater := appgateway.NewUpdater(repo, registrymocks.NewRepository(t), newCacheManager(), publisher, nil, newTestLogger(), nil, false, nil)
	_, err := updater.Update(context.Background(), appgateway.UpdateInput{
		ID:              id,
		TrafficLabeling: &trafficlabel.Config{Enabled: false, RegistryID: ids.New[ids.RegistryKind]().String(), Model: "m"},
	})
	require.NoError(t, err)
}

func TestUpdater_Update_TrafficLabeling_KeepsAndClears(t *testing.T) {
	t.Parallel()
	stored := &trafficlabel.Config{Enabled: true, RegistryID: ids.New[ids.RegistryKind]().String(), Model: "m"}

	t.Run("keeps the config when omitted, without checking the registry again", func(t *testing.T) {
		t.Parallel()
		repo := repomocks.NewRepository(t)
		id := ids.New[ids.GatewayKind]()
		now := time.Now().UTC()
		existing := domain.Rehydrate(id, "gw", "active", "", nil, nil, nil, now, now)
		existing.TrafficLabeling = stored
		repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
		repo.EXPECT().
			Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool { return g.TrafficLabeling == stored })).
			Return(nil).
			Once()
		publisher := cachemocks.NewEventPublisher(t)
		publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()

		updater := appgateway.NewUpdater(repo, registrymocks.NewRepository(t), newCacheManager(), publisher, nil, newTestLogger(), nil, false, nil)
		_, err := updater.Update(context.Background(), appgateway.UpdateInput{ID: id, Slug: ptr("renamed")})
		require.NoError(t, err)
	})

	t.Run("clears the config on an explicit null", func(t *testing.T) {
		t.Parallel()
		repo := repomocks.NewRepository(t)
		id := ids.New[ids.GatewayKind]()
		now := time.Now().UTC()
		existing := domain.Rehydrate(id, "gw", "active", "", nil, nil, nil, now, now)
		existing.TrafficLabeling = stored
		repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()
		repo.EXPECT().
			Update(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool { return g.TrafficLabeling == nil })).
			Return(nil).
			Once()
		publisher := cachemocks.NewEventPublisher(t)
		publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()

		updater := appgateway.NewUpdater(repo, registrymocks.NewRepository(t), newCacheManager(), publisher, nil, newTestLogger(), nil, false, nil)
		got, err := updater.Update(context.Background(), appgateway.UpdateInput{ID: id, ClearTrafficLabeling: true})
		require.NoError(t, err)
		assert.Nil(t, got.TrafficLabeling)
	})

	t.Run("rejects an invalid config without persisting", func(t *testing.T) {
		t.Parallel()
		repo := repomocks.NewRepository(t)
		id := ids.New[ids.GatewayKind]()
		now := time.Now().UTC()
		existing := domain.Rehydrate(id, "gw", "active", "", nil, nil, nil, now, now)
		repo.EXPECT().FindByID(mock.Anything, id).Return(existing, nil).Once()

		updater := appgateway.NewUpdater(repo, registrymocks.NewRepository(t), newCacheManager(), cachemocks.NewEventPublisher(t), nil, newTestLogger(), nil, false, nil)
		_, err := updater.Update(context.Background(), appgateway.UpdateInput{ID: id, TrafficLabeling: &trafficlabel.Config{Enabled: true}})
		require.ErrorIs(t, err, commonerrors.ErrValidation)
	})
}

func TestCreator_Create_TrafficLabeling(t *testing.T) {
	t.Parallel()

	t.Run("a disabled config is stored normalized", func(t *testing.T) {
		t.Parallel()
		repo := repomocks.NewRepository(t)
		expectNoSiblingGateways(repo, "acme")
		repo.EXPECT().
			SaveWithTenantCap(mock.Anything, mock.MatchedBy(func(g *domain.Gateway) bool {
				tl := g.TrafficLabeling
				return tl != nil && !tl.Enabled && tl.Model == "gpt-4o-mini" && tl.MessageWindow == trafficlabel.DefaultMessageWindow
			}), "acme", 0).
			Return(nil).
			Once()

		in := &trafficlabel.Config{Enabled: false, Model: " gpt-4o-mini "}
		creator := appgateway.NewCreator(repo, registrymocks.NewRepository(t), newCacheManager(), nil, newTestLogger(), nil, true, nil)
		_, err := creator.Create(context.Background(), appgateway.CreateInput{Slug: "prod", TenantID: "acme", TrafficLabeling: in})
		require.NoError(t, err)
		assert.Equal(t, " gpt-4o-mini ", in.Model, "Create must not mutate the caller's config")
	})

	t.Run("an enabled config needs a registry of the new gateway", func(t *testing.T) {
		t.Parallel()
		repo := repomocks.NewRepository(t)
		expectNoSiblingGateways(repo, "acme")
		other := classifierRegistry(ids.New[ids.GatewayKind]())
		registries := registrymocks.NewRepository(t)
		registries.EXPECT().FindByID(mock.Anything, other.ID).Return(other, nil).Once()

		creator := appgateway.NewCreator(repo, registries, newCacheManager(), nil, newTestLogger(), nil, true, nil)
		_, err := creator.Create(context.Background(), appgateway.CreateInput{Slug: "prod", TenantID: "acme", TrafficLabeling: labelingFor(other)})
		require.ErrorIs(t, err, appgateway.ErrInvalidTrafficLabelingRegistry)
	})
}
