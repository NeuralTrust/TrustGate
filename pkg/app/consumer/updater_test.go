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

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	authmocks "github.com/NeuralTrust/AgentGateway/pkg/domain/auth/mocks"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
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
		})).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, authmocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
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
		})).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, authmocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
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

	updater := appconsumer.NewUpdater(repo, authmocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID: ids.New[ids.ConsumerKind](),
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestUpdater_Update_RejectsModelPolicyForUnassociatedRegistry(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := appconsumer.NewUpdater(repo, authmocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

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
}

func TestUpdater_Update_AllowsModelPolicyForAssociatedRegistry(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Once()

	updater := appconsumer.NewUpdater(repo, authmocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

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

	updater := appconsumer.NewUpdater(repo, authmocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

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
		})).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, authmocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
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
		})).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, authmocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
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
		})).
		Return(nil).
		Once()

	updater := appconsumer.NewUpdater(repo, authmocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
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
		Return([]*authdomain.Auth{{ID: authID, GatewayID: gwID, Type: authdomain.TypeIDP}}, nil).Once()

	updater := appconsumer.NewUpdater(repo, authRepo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Type:      ptr(domain.TypeMCP),
	})
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict (idp cannot broker for an MCP consumer)", err)
	}
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

	updater := appconsumer.NewUpdater(repo, authRepo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:          existing.ID,
		GatewayID:   gwID,
		RoutingMode: &mode,
	})
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict (role_based requires an identity-provider auth)", err)
	}
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
	repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Once()

	authRepo := authmocks.NewRepository(t)
	authRepo.EXPECT().FindByIDs(mock.Anything, gwID, existing.AuthIDs).
		Return([]*authdomain.Auth{{ID: authID, GatewayID: gwID, Type: authdomain.TypeOAuth2}}, nil).Once()

	updater := appconsumer.NewUpdater(repo, authRepo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
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

	updater := appconsumer.NewUpdater(repo, authmocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:          existing.ID,
		GatewayID:   gwID,
		RoutingMode: &mode,
	})
	if !errors.Is(err, domain.ErrInvalidRoutingMode) {
		t.Fatalf("err = %v, want ErrInvalidRoutingMode (role_based allows at most one auth)", err)
	}
}

func TestUpdater_Update_RejectsCrossGateway(t *testing.T) {
	t.Parallel()
	gwID, otherGW := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, beID)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	updater := appconsumer.NewUpdater(repo, authmocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: otherGW,
		Name:      ptr("n"),
	})
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}
