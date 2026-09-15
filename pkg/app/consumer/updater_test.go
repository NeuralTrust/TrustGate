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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
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
		}), mock.Anything, mock.Anything).
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
				c.Type == domain.TypeLLM &&
				len(c.RegistryIDs) == 1 && c.RegistryIDs[0] == beID
		}), (*domain.RegistryBindings)(nil), (*[]ids.AuthID)(nil)).
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
	if got.Slug != "X84Yhsy8" {
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
	repo.EXPECT().Update(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

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
		}), mock.Anything, mock.Anything).
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

// Switching a consumer to MCP while it carries a provider stored under the
// deprecated alias is accepted: the alias is oauth2, which is the type MCP
// takes. Whether that provider can broker an interactive login is a capability
// question the protected-resource metadata answers; it is not a reason to
// refuse a credential a client may already hold a token for.
func TestUpdater_Update_AllowsAliasedIdPAuthOnSwitchToMCP(t *testing.T) {
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

	repo.EXPECT().Update(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()
	updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authRepo, newCacheManager(), publisher, newTestLogger(), nil)
	if _, err := updater.Update(context.Background(), appconsumer.UpdateInput{
		ID:        existing.ID,
		GatewayID: gwID,
		Type:      ptr(domain.TypeMCP),
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
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
	repo.EXPECT().Update(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()

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

func TestUpdater_Update_ReplacesRegistriesWithWeights(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	existing := existingConsumer(gwID, ids.New[ids.RegistryKind]())

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().
		Update(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return len(c.RegistryIDs) == 1 && c.RegistryIDs[0] == beID &&
				c.WeightFor(beID) == 30
		}), mock.MatchedBy(func(b *domain.RegistryBindings) bool {
			return b != nil && len(b.IDs) == 1 && b.IDs[0] == beID && b.Weights[beID] == 30
		}), (*[]ids.AuthID)(nil)).
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
		ID:        existing.ID,
		GatewayID: gwID,
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
		}), (*[]ids.AuthID)(nil)).
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

func mcpConsumerWithAuths(gwID ids.GatewayID, beID ids.RegistryID, identity domain.Identity, authIDs []ids.AuthID) *domain.Consumer {
	now := time.Now().UTC()
	return domain.Rehydrate(domain.RehydrateParams{
		ID:          ids.New[ids.ConsumerKind](),
		GatewayID:   gwID,
		Name:        "mcp",
		Type:        domain.TypeMCP,
		Slug:        "X84Yhsy8",
		Active:      true,
		RegistryIDs: []ids.RegistryID{beID},
		AuthIDs:     authIDs,
		Identity:    identity,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
}

// An identity switch and the auth replacement it needs must land in one
// request: the new pair is what gets validated, so the consumer is never
// persisted in the broken intermediate state the two-request dance produced
// (RUN-1501).
func TestUpdater_Update_IdentityTransitionReplacesAuths(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	beID := ids.New[ids.RegistryKind]()
	apiKeyID := ids.New[ids.AuthKind]()
	idpID := ids.New[ids.AuthKind]()
	apiKey := &authdomain.Auth{ID: apiKeyID, GatewayID: gwID, Type: authdomain.TypeAPIKey, Enabled: true}
	idp := &authdomain.Auth{
		ID: idpID, GatewayID: gwID, Type: authdomain.TypeOAuth2, Enabled: true,
		Config: authdomain.Config{OAuth2: &authdomain.OAuth2Config{
			Issuer:   "https://idp.example.com",
			JWKSURL:  "https://idp.example.com/jwks",
			ClientID: "gateway-client",
		}},
	}
	platformUsers := domain.Identity{ActsForUsers: true, Source: domain.IdentitySourcePlatform}
	appUsers := domain.Identity{ActsForUsers: true, Source: domain.IdentitySourceApp}

	foreignAuthID := ids.New[ids.AuthKind]()

	tests := []struct {
		name           string
		startIdentity  domain.Identity
		startAuths     []ids.AuthID
		identity       *domain.Identity
		auths          *[]ids.AuthID
		lookup         []*authdomain.Auth
		previousLookup []*authdomain.Auth
		wantWarn       bool
		wantErr        error
		wantAuthIDs    []ids.AuthID
	}{
		{
			name:        "acts for users while swapping the api key for an idp",
			startAuths:  []ids.AuthID{apiKeyID},
			identity:    &platformUsers,
			auths:       &[]ids.AuthID{idpID},
			lookup:      []*authdomain.Auth{idp},
			wantAuthIDs: []ids.AuthID{idpID},
		},
		{
			name:        "app users while swapping the idp for an api key",
			startAuths:  []ids.AuthID{idpID},
			identity:    &appUsers,
			auths:       &[]ids.AuthID{apiKeyID},
			lookup:      []*authdomain.Auth{apiKey},
			wantAuthIDs: []ids.AuthID{apiKeyID},
		},
		{
			name:           "acts for users while detaching every auth",
			startAuths:     []ids.AuthID{apiKeyID},
			identity:       &platformUsers,
			auths:          &[]ids.AuthID{},
			previousLookup: []*authdomain.Auth{apiKey},
			wantAuthIDs:    []ids.AuthID{},
		},
		// Detaching the identity provider from a platform-users consumer moves
		// it from "only this provider gets in" to "any built-in default-IdP
		// login gets in". It is a legitimate admin action within one tenant, so
		// it is logged rather than refused (RUN-1501).
		{
			name:           "detaching the idp from a platform users consumer is logged",
			startIdentity:  platformUsers,
			startAuths:     []ids.AuthID{idpID},
			auths:          &[]ids.AuthID{},
			previousLookup: []*authdomain.Auth{idp},
			wantWarn:       true,
			wantAuthIDs:    []ids.AuthID{},
		},
		{
			name:          "replacing auths with an id from another gateway",
			startIdentity: platformUsers,
			startAuths:    []ids.AuthID{idpID},
			auths:         &[]ids.AuthID{foreignAuthID},
			lookup:        []*authdomain.Auth{},
			wantErr:       commonerrors.ErrConflict,
		},
		{
			name:       "acts for users keeping an incompatible api key",
			startAuths: []ids.AuthID{apiKeyID},
			identity:   &platformUsers,
			lookup:     []*authdomain.Auth{apiKey},
			wantErr:    commonerrors.ErrConflict,
		},
		{
			name:          "replacing auths with an incompatible one on an unchanged identity",
			startIdentity: platformUsers,
			startAuths:    []ids.AuthID{idpID},
			auths:         &[]ids.AuthID{apiKeyID},
			lookup:        []*authdomain.Auth{apiKey},
			wantErr:       commonerrors.ErrConflict,
		},
		{
			name:          "omitting auths leaves the links untouched",
			startIdentity: platformUsers,
			startAuths:    []ids.AuthID{idpID},
			auths:         nil,
			wantAuthIDs:   []ids.AuthID{idpID},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			existing := mcpConsumerWithAuths(gwID, beID, tt.startIdentity, tt.startAuths)

			repo := repomocks.NewRepository(t)
			repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

			authRepo := authmocks.NewRepository(t)
			if tt.lookup != nil {
				wantLookup := tt.startAuths
				if tt.auths != nil {
					wantLookup = *tt.auths
				}
				authRepo.EXPECT().FindByIDs(mock.Anything, gwID, wantLookup).Return(tt.lookup, nil).Once()
			}
			if tt.previousLookup != nil {
				authRepo.EXPECT().FindByIDs(mock.Anything, gwID, tt.startAuths).Return(tt.previousLookup, nil).Once()
			}

			publisher := cachemocks.NewEventPublisher(t)
			if tt.wantErr == nil {
				repo.EXPECT().
					Update(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
						return slices.Equal(c.AuthIDs, tt.wantAuthIDs)
					}), (*domain.RegistryBindings)(nil), mock.MatchedBy(func(a *[]ids.AuthID) bool {
						if tt.auths == nil {
							return a == nil
						}
						return a != nil && slices.Equal(*a, tt.wantAuthIDs)
					})).
					Return(nil).
					Once()
				publisher.EXPECT().
					Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
					Return(nil).
					Once()
			}

			var logged bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn}))
			updater := appconsumer.NewUpdater(repo, registrymocks.NewRepository(t), authRepo, newCacheManager(), publisher, logger, nil)
			got, err := updater.Update(context.Background(), appconsumer.UpdateInput{
				ID:        existing.ID,
				GatewayID: gwID,
				Identity:  tt.identity,
				Auths:     tt.auths,
			})
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
				repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
				return
			}
			if err != nil {
				t.Fatalf("Update error: %v", err)
			}
			if !slices.Equal(got.AuthIDs, tt.wantAuthIDs) {
				t.Fatalf("AuthIDs = %v, want %v", got.AuthIDs, tt.wantAuthIDs)
			}
			warned := strings.Contains(logged.String(), "detached its identity provider")
			if warned != tt.wantWarn {
				t.Fatalf("widening warning logged = %v, want %v (log: %q)", warned, tt.wantWarn, logged.String())
			}
		})
	}
}
