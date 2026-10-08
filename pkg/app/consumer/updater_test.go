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

package consumer_test

import (
	"context"
	"errors"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	authmocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	registrymocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

func ptr[T any](v T) *T { return &v }

func existingConsumer(gwID ids.GatewayID, beID ids.RegistryID) *domain.Consumer {
	now := time.Now().UTC()
	return domain.Rehydrate(domain.RehydrateParams{
		ID:          ids.New[ids.ConsumerKind](),
		GatewayID:   gwID,
		Name:        "old",
		Type:        domain.TypeLLM,
		Slug:        "X84Yhsy8",
		RoutingMode: domain.RoutingModeInline,
		Active:      true,
		RegistryIDs: []ids.RegistryID{beID},
		CreatedAt:   now,
		UpdatedAt:   now,
	})
}

func TestUpdater_Update_Success(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.ID == existing.ID && c.Name == "new" && c.Type == domain.TypeMCP &&
				len(c.RegistryIDs) == 1 && c.RegistryIDs[0] == beID
		}), mock.Anything).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	got, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Name:      ptr("new"),
		Type:      ptr(domain.TypeMCP),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Name != "new" || got.Type != domain.TypeMCP {
		t.Fatalf("not applied: %+v", got)
	}
}

func TestUpdater_Update_Partial_PreservesFieldsAndAssociations(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.Name == "renamed" && c.Slug == "X84Yhsy8" &&
				c.RoutingMode == domain.RoutingModeInline && c.Type == domain.TypeLLM &&
				len(c.RegistryIDs) == 1 && c.RegistryIDs[0] == beID
		}), (*domain.RegistryBindings)(nil)).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	got, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Name:      ptr("renamed"),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Slug != "X84Yhsy8" || got.RoutingMode != domain.RoutingModeInline {
		t.Fatalf("fields not preserved: %+v", got)
	}
	if len(got.RegistryIDs) != 1 || got.RegistryIDs[0] != beID {
		t.Fatalf("associations not preserved: %+v", got.RegistryIDs)
	}
}

func TestUpdater_Update_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, mock.Anything).Return(nil, domain.ErrNotFound).Once()

	publisher := cachemocks.NewEventPublisher(t)
	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID: ids.New[ids.ConsumerKind](),
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestUpdater_Update_RejectsModelPolicyForUnassociatedRegistry(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Name:      ptr("n"),
		Type:      ptr(domain.TypeLLM),
		ModelPolicies: ptr(domain.ModelPolicies{
			ids.New[ids.RegistryKind](): {},
		}),
	})
	if !errors.Is(err, registrydomain.ErrInvalidRegistryID) {
		t.Fatalf("err = %v, want ErrInvalidRegistryID", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestUpdater_Update_AllowsModelPolicyForAssociatedRegistry(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Name:      ptr("n"),
		Type:      ptr(domain.TypeLLM),
		ModelPolicies: ptr(domain.ModelPolicies{
			beID: {Allowed: []string{"gpt-4o"}, Default: "gpt-4o"},
		}),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

func TestUpdater_Update_RejectsLBConfigForUnassociatedRegistry(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	unassociatedID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		LBConfig: &domain.LBConfig{
			Enabled: true,
			Members: []domain.LBPoolMember{{RegistryID: unassociatedID, Models: []string{"gpt-4o"}}},
		},
		ModelPolicies: ptr(domain.ModelPolicies{
			beID: {Allowed: []string{"gpt-4o"}},
		}),
	})
	if !errors.Is(err, registrydomain.ErrInvalidRegistryID) {
		t.Fatalf("err = %v, want ErrInvalidRegistryID", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestUpdater_Update_DisabledObjectsClearFallbackAndLBConfig(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)
	existing.Fallback = &domain.Fallback{
		Enabled:  true,
		Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
		Budget:   domain.FallbackBudget{MaxAttempts: 3},
		Chain:    []ids.RegistryID{beID},
	}
	existing.ModelPolicies = domain.ModelPolicies{beID: {Allowed: []string{"gpt-4o"}}}
	existing.LBConfig = &domain.LBConfig{
		Enabled: true,
		Members: []domain.LBPoolMember{{RegistryID: beID, Models: []string{"gpt-4o"}}},
	}

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.Fallback != nil && !c.Fallback.Enabled && len(c.Fallback.Chain) == 0 &&
				c.LBConfig != nil && !c.LBConfig.Enabled && len(c.LBConfig.Members) == 0
		}), mock.Anything).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Fallback:  &domain.Fallback{Enabled: false},
		LBConfig:  &domain.LBConfig{Enabled: false},
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

func TestUpdater_Update_SwitchToRoleBasedCleansInlineConfig(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)
	existing.Fallback = &domain.Fallback{Enabled: true, Chain: []ids.RegistryID{beID}, Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx}}
	existing.ModelPolicies = domain.ModelPolicies{beID: {Allowed: []string{"gpt-4o"}}}
	existing.LBConfig = &domain.LBConfig{Enabled: true, Members: []domain.LBPoolMember{{RegistryID: beID, Models: []string{"gpt-4o"}}}}
	mode := domain.RoutingModeRoleBased

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.RoutingMode == domain.RoutingModeRoleBased &&
				len(c.RegistryIDs) == 0 &&
				c.Fallback == nil &&
				c.LBConfig == nil &&
				len(c.ModelPolicies) == 0
		}), mock.Anything).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	if _, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:          existing.ID,
		GatewayID:   gwID,
		RoutingMode: &mode,
	}); err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

func TestUpdater_Update_SwitchToInlineClearsRoles(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	now := time.Now().UTC()
	existing := domain.Rehydrate(domain.RehydrateParams{
		ID:          ids.New[ids.ConsumerKind](),
		GatewayID:   gwID,
		Name:        "old",
		Type:        domain.TypeLLM,
		Slug:        "X84Yhsy8",
		RoutingMode: domain.RoutingModeRoleBased,
		Active:      true,
		RoleIDs:     []ids.RoleID{ids.New[ids.RoleKind]()},
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	mode := domain.RoutingModeInline

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.RoutingMode == domain.RoutingModeInline && len(c.RoleIDs) == 0
		}), mock.Anything).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	if _, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:          existing.ID,
		GatewayID:   gwID,
		RoutingMode: &mode,
	}); err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

func TestUpdater_Update_RejectsIdPAuthOnSwitchToMCP(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	authID := ids.New[ids.AuthKind]()
	existing := existingConsumer(gwID, beID)
	existing.AuthIDs = []ids.AuthID{authID}

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	authRepo := authmocks.NewRepository(t)
	authRepo.EXPECT().FindByIDs(mock.Anything, gwID, existing.AuthIDs).
		Return([]*authdomain.Auth{{ID: authID, GatewayID: gwID, Type: authdomain.TypeOIDC}}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authRepo, newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Type:      ptr(domain.TypeMCP),
	})
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict (oidc cannot broker for an MCP consumer)", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestUpdater_Update_RejectsNonIdPAuthOnSwitchToRoleBased(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	authID := ids.New[ids.AuthKind]()
	existing := existingConsumer(gwID, beID)
	existing.AuthIDs = []ids.AuthID{authID}
	mode := domain.RoutingModeRoleBased

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	authRepo := authmocks.NewRepository(t)
	authRepo.EXPECT().FindByIDs(mock.Anything, gwID, existing.AuthIDs).
		Return([]*authdomain.Auth{{ID: authID, GatewayID: gwID, Type: authdomain.TypeAPIKey}}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authRepo, newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:          existing.ID,
		GatewayID:   gwID,
		RoutingMode: &mode,
	})
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict (role_based requires an identity-provider auth)", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestUpdater_Update_AllowsOAuth2AuthOnSwitchToMCP(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	authID := ids.New[ids.AuthKind]()
	existing := existingConsumer(gwID, beID)
	existing.AuthIDs = []ids.AuthID{authID}

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

	authRepo := authmocks.NewRepository(t)
	authRepo.EXPECT().FindByIDs(mock.Anything, gwID, existing.AuthIDs).
		Return([]*authdomain.Auth{{ID: authID, GatewayID: gwID, Type: authdomain.TypeOAuth2}}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authRepo, newCacheManager(), publisher, newTestLogger(), nil)
	if _, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Type:      ptr(domain.TypeMCP),
	}); err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

func TestUpdater_Update_RejectsMultipleAuthsOnSwitchToRoleBased(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)
	existing.AuthIDs = []ids.AuthID{ids.New[ids.AuthKind](), ids.New[ids.AuthKind]()}
	mode := domain.RoutingModeRoleBased

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:          existing.ID,
		GatewayID:   gwID,
		RoutingMode: &mode,
	})
	if !errors.Is(err, domain.ErrInvalidRoutingMode) {
		t.Fatalf("err = %v, want ErrInvalidRoutingMode (role_based allows at most one auth)", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func roleBasedConsumer(gwID ids.GatewayID) *domain.Consumer {
	now := time.Now().UTC()
	return domain.Rehydrate(domain.RehydrateParams{
		ID:          ids.New[ids.ConsumerKind](),
		GatewayID:   gwID,
		Name:        "old",
		Type:        domain.TypeLLM,
		Slug:        "X84Yhsy8",
		RoutingMode: domain.RoutingModeRoleBased,
		Active:      true,
		RoleIDs:     []ids.RoleID{ids.New[ids.RoleKind]()},
		CreatedAt:   now,
		UpdatedAt:   now,
	})
}

func TestUpdater_Update_SwitchToInlineAttachesRegistries(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := roleBasedConsumer(gwID)
	mode := domain.RoutingModeInline

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.RoutingMode == domain.RoutingModeInline &&
				len(c.RoleIDs) == 0 &&
				len(c.RegistryIDs) == 1 && c.RegistryIDs[0] == beID &&
				c.WeightFor(beID) == 30
		}), mock.MatchedBy(func(b *domain.RegistryBindings) bool {
			return b != nil && len(b.IDs) == 1 && b.IDs[0] == beID && b.Weights[beID] == 30
		})).
		Return(nil).
		Once()

	registryRepo := registrymocks.NewRepository(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, []ids.RegistryID{beID}).
		Return([]*registrydomain.Registry{{ID: beID, GatewayID: gwID}}, nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, registryRepo, authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	got, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:          existing.ID,
		GatewayID:   gwID,
		RoutingMode: &mode,
		Registries: &domain.RegistryBindings{
			IDs:     []ids.RegistryID{beID},
			Weights: map[ids.RegistryID]int{beID: 30},
		},
		ModelPolicies: ptr(domain.ModelPolicies{beID: {Allowed: []string{"gpt-4o"}}}),
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if len(got.RegistryIDs) != 1 || got.RegistryIDs[0] != beID {
		t.Fatalf("RegistryIDs = %v, want [%s]", got.RegistryIDs, beID)
	}
}

func TestUpdater_Update_EmptyRegistriesDetachesAll(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return len(c.RegistryIDs) == 0
		}), mock.MatchedBy(func(b *domain.RegistryBindings) bool {
			return b != nil && len(b.IDs) == 0
		})).
		Return(nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	if _, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:         existing.ID,
		GatewayID:  gwID,
		Registries: &domain.RegistryBindings{},
	}); err != nil {
		t.Fatalf("Update error: %v", err)
	}
}

func TestUpdater_Update_RejectsRegistriesInRoleBasedMode(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := roleBasedConsumer(gwID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:         existing.ID,
		GatewayID:  gwID,
		Registries: &domain.RegistryBindings{IDs: []ids.RegistryID{beID}},
	})
	if !errors.Is(err, domain.ErrInvalidRoutingMode) {
		t.Fatalf("err = %v, want ErrInvalidRoutingMode (registries need inline routing)", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestUpdater_Update_RejectsRegistriesOutsideGateway(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	foreignID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	registryRepo := registrymocks.NewRepository(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, []ids.RegistryID{foreignID}).
		Return(nil, nil).
		Once()

	publisher := cachemocks.NewEventPublisher(t)
	updater := appconsumer.NewUpdater(repo, registryRepo, authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:         existing.ID,
		GatewayID:  gwID,
		Registries: &domain.RegistryBindings{IDs: []ids.RegistryID{foreignID}},
	})
	if !errors.Is(err, registrydomain.ErrInvalidRegistryID) {
		t.Fatalf("err = %v, want ErrInvalidRegistryID", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestUpdater_Update_RejectsCrossGateway(t *testing.T) {
	t.Parallel()
	gwID, otherGW := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: otherGW,
		Name:      ptr("n"),
	})
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestUpdaterExplicitDisabledSmartRoutingUsesEffectivePolicy(t *testing.T) {
	gw, id, unknown := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	for _, tc := range []struct {
		name   string
		tierID ids.RegistryID
	}{
		{"stored policy rejects model", id},
		{"unknown tier registry", unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			existing := existingConsumer(gw, id)
			existing.ModelPolicies = domain.ModelPolicies{id: {Allowed: []string{"low"}}}
			repo := repomocks.NewRepository(t)
			repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
			publisher := cachemocks.NewEventPublisher(t)
			updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
			cfg := &domain.LBConfig{Algorithm: "smart-routing", Members: []domain.LBPoolMember{{RegistryID: id, Model: "low"}, {RegistryID: id, Model: "high"}}, SmartRouting: &registrydomain.SmartRoutingConfig{SR1: &registrydomain.SR1Config{CacheTTLSeconds: 30}, Tiers: []registrydomain.SmartRoutingTier{{RegistryID: tc.tierID, Model: "low", MinScore: 0}, {RegistryID: id, Model: "high", MinScore: .45}}}}
			_, err := updater.Update(context.Background(), appconsumer.UpdateInput{ID: existing.ID, LBConfig: cfg})
			if !errors.Is(err, domain.ErrInvalidLBConfig) {
				t.Fatalf("error=%v want invalid config", err)
			}
			if cfg.Enabled {
				t.Fatal("validation enabled the caller config")
			}
			repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
		})
	}
}

func TestUpdaterRetainsMigratedLadderWithoutClientMarker(t *testing.T) {
	gw, id := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	existing := existingConsumer(gw, id)
	existing.ModelPolicies = domain.ModelPolicies{id: {Allowed: []string{"low", "middle", "upper", "high"}}}
	existing.LBConfig = &domain.LBConfig{Enabled: true, Algorithm: "smart-routing", SmartRouting: &registrydomain.SmartRoutingConfig{LegacyThresholds: true, SR1: &registrydomain.SR1Config{CacheTTLSeconds: 300}}}
	for i, cut := range []float64{.12, .34, .72, .97} {
		model := []string{"low", "middle", "upper", "high"}[i]
		existing.LBConfig.Members = append(existing.LBConfig.Members, domain.LBPoolMember{RegistryID: id, Model: model})
		existing.LBConfig.SmartRouting.Tiers = append(existing.LBConfig.SmartRouting.Tiers, registrydomain.SmartRoutingTier{RegistryID: id, Model: model, MinScore: cut})
	}
	next := *existing.LBConfig
	shape := *next.SmartRouting
	shape.LegacyThresholds = false
	next.SmartRouting = &shape
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
		return c.LBConfig.SmartRouting.LegacyThresholds && len(c.LBConfig.SmartRouting.Tiers) == 4 && c.LBConfig.SmartRouting.Tiers[3].MinScore == .97
	}), (*domain.RegistryBindings)(nil)).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gw.String()}).Return(nil).Once()
	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	if _, err := updater.Update(context.Background(), appconsumer.UpdateInput{ID: existing.ID, LBConfig: &next}); err != nil {
		t.Fatal(err)
	}
}

func TestUpdaterOmittedDisabledLegacyRoutingAllowsNameEdit(t *testing.T) {
	gw, id, unknown := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind](), ids.New[ids.RegistryKind]()
	existing := existingConsumer(gw, id)
	existing.ModelPolicies = domain.ModelPolicies{id: {Allowed: []string{"low"}}}
	existing.LBConfig = &domain.LBConfig{Algorithm: "smart-routing", Members: []domain.LBPoolMember{{RegistryID: id, Model: "low"}}, SmartRouting: &registrydomain.SmartRoutingConfig{Tiers: []registrydomain.SmartRoutingTier{{RegistryID: unknown, MinScore: .8}}}}
	original := existing.LBConfig
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
		return c.Name == "renamed" && c.LBConfig == original && !c.LBConfig.Enabled && c.LBConfig.SmartRouting.SR1 == nil && c.LBConfig.SmartRouting.Tiers[0].MinScore == .8
	}), (*domain.RegistryBindings)(nil)).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gw.String()}).Return(nil).Once()
	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	if _, err := updater.Update(context.Background(), appconsumer.UpdateInput{ID: existing.ID, Name: ptr("renamed")}); err != nil {
		t.Fatal(err)
	}
}

func TestUpdaterDisabledSmartRoutingPolicyEditCannotInvalidatePins(t *testing.T) {
	gw, id := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	existing := existingConsumer(gw, id)
	existing.ModelPolicies = domain.ModelPolicies{id: {Allowed: []string{"low", "high"}}}
	existing.LBConfig = &domain.LBConfig{Algorithm: "smart-routing", Members: []domain.LBPoolMember{{RegistryID: id, Model: "low"}, {RegistryID: id, Model: "high"}}, SmartRouting: &registrydomain.SmartRoutingConfig{SR1: &registrydomain.SR1Config{CacheTTLSeconds: 30}, Tiers: []registrydomain.SmartRoutingTier{{RegistryID: id, Model: "low", MinScore: 0}, {RegistryID: id, Model: "high", MinScore: .45}}}}
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authmocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	policies := domain.ModelPolicies{id: {Allowed: []string{"low"}}}
	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{ID: existing.ID, ModelPolicies: &policies})
	if !errors.Is(err, domain.ErrInvalidLBConfig) {
		t.Fatalf("policy edit error=%v want invalid config", err)
	}
	if existing.LBConfig.Enabled {
		t.Fatal("validation enabled the stored pool")
	}
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}
