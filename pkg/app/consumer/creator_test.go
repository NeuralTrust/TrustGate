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
	"io"
	"log/slog"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	registrymocks "github.com/NeuralTrust/AgentGateway/pkg/domain/registry/mocks"
	roledomain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
	rolemocks "github.com/NeuralTrust/AgentGateway/pkg/domain/role/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newCacheManager() *cache.TTLMapManager {
	return cache.NewTTLMapManager(time.Hour)
}

func TestCreator_Create_Success(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.GatewayID == gwID && c.Name == "chat" && c.Type == domain.TypeLLM
		})).
		Return(nil).
		Once()

	mgr := newCacheManager()
	creator := appconsumer.NewCreator(repo, registrymocks.NewRepository(t), rolemocks.NewRepository(t), mgr, cachetest.NoopPublisher(), newTestLogger())

	c, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID: gwID,
		Name:      "chat",
		Type:      domain.TypeLLM,
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	// Consumers are created bare; registries are attached afterwards.
	if len(c.RegistryIDs) != 0 {
		t.Fatalf("RegistryIDs = %v, want empty at creation", c.RegistryIDs)
	}
	cached, ok := mgr.GetTTLMap(cache.ConsumerTTLName).Get(c.ID.String())
	if !ok {
		t.Fatal("created consumer was not pre-warmed in the cache")
	}
	if cached.(*domain.Consumer).ID != c.ID {
		t.Fatal("cached consumer ID mismatch")
	}
}

func TestCreator_Create_WithRegistries_BindsAtomically(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return len(c.RegistryIDs) == 1 && c.RegistryIDs[0] == registryID
		})).
		Return(nil).
		Once()

	registryRepo := registrymocks.NewRepository(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, []ids.RegistryID{registryID}).
		Return([]*registrydomain.Registry{{ID: registryID, GatewayID: gwID}}, nil).
		Once()

	creator := appconsumer.NewCreator(repo, registryRepo, rolemocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	c, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID:     gwID,
		Name:          "chat",
		Type:          domain.TypeLLM,
		RegistryIDs:   []ids.RegistryID{registryID},
		ModelPolicies: domain.ModelPolicies{registryID: {Allowed: []string{"gpt-4o"}}},
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if len(c.RegistryIDs) != 1 || c.RegistryIDs[0] != registryID {
		t.Fatalf("RegistryIDs = %v, want [%s]", c.RegistryIDs, registryID)
	}
}

func TestCreator_Create_WithRoles_BindsAtomically(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	roleID := ids.New[ids.RoleKind]()

	repo := repomocks.NewRepository(t)
	repo.EXPECT().
		Save(mock.Anything, mock.MatchedBy(func(c *domain.Consumer) bool {
			return c.RoutingMode == domain.RoutingModeRoleBased &&
				len(c.RoleIDs) == 1 && c.RoleIDs[0] == roleID
		})).
		Return(nil).
		Once()

	roleRepo := rolemocks.NewRepository(t)
	roleRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, []ids.RoleID{roleID}).
		Return([]*roledomain.Role{{ID: roleID, GatewayID: gwID}}, nil).
		Once()

	creator := appconsumer.NewCreator(repo, registrymocks.NewRepository(t), roleRepo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	c, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID:   gwID,
		Name:        "role-chat",
		Type:        domain.TypeLLM,
		RoutingMode: domain.RoutingModeRoleBased,
		RoleIDs:     []ids.RoleID{roleID},
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if len(c.RoleIDs) != 1 || c.RoleIDs[0] != roleID {
		t.Fatalf("RoleIDs = %v, want [%s]", c.RoleIDs, roleID)
	}
}

func TestCreator_Create_RejectsRoleFromAnotherGateway(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	roleID := ids.New[ids.RoleKind]()

	roleRepo := rolemocks.NewRepository(t)
	roleRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, []ids.RoleID{roleID}).
		Return(nil, nil).
		Once()

	creator := appconsumer.NewCreator(repomocks.NewRepository(t), registrymocks.NewRepository(t), roleRepo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID:   gwID,
		Name:        "role-chat",
		Type:        domain.TypeLLM,
		RoutingMode: domain.RoutingModeRoleBased,
		RoleIDs:     []ids.RoleID{roleID},
	})
	if !errors.Is(err, roledomain.ErrInvalidRoleID) {
		t.Fatalf("err = %v, want ErrInvalidRoleID", err)
	}
}

func TestCreator_Create_RejectsRolesInInlineMode(t *testing.T) {
	t.Parallel()
	creator := appconsumer.NewCreator(repomocks.NewRepository(t), registrymocks.NewRepository(t), rolemocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID:   ids.New[ids.GatewayKind](),
		Name:        "inline-with-roles",
		Type:        domain.TypeLLM,
		RoutingMode: domain.RoutingModeInline,
		RoleIDs:     []ids.RoleID{ids.New[ids.RoleKind]()},
	})
	if !errors.Is(err, domain.ErrInvalidRoutingMode) {
		t.Fatalf("err = %v, want ErrInvalidRoutingMode", err)
	}
}

func TestCreator_Create_RejectsRegistryFromAnotherGateway(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()

	registryRepo := registrymocks.NewRepository(t)
	registryRepo.EXPECT().
		FindByIDs(mock.Anything, gwID, []ids.RegistryID{registryID}).
		Return(nil, nil).
		Once()

	creator := appconsumer.NewCreator(repomocks.NewRepository(t), registryRepo, rolemocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID:   gwID,
		Name:        "chat",
		Type:        domain.TypeLLM,
		RegistryIDs: []ids.RegistryID{registryID},
	})
	if !errors.Is(err, registrydomain.ErrInvalidRegistryID) {
		t.Fatalf("err = %v, want ErrInvalidRegistryID", err)
	}
}

func TestCreator_Create_RejectsRegistryReferencesBeforeAssociation(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	registryID := ids.New[ids.RegistryKind]()

	cases := []struct {
		name    string
		input   appconsumer.CreateInput
		wantErr error
	}{
		{
			name: "fallback chain",
			input: appconsumer.CreateInput{
				Fallback: &domain.Fallback{
					Enabled:  true,
					Triggers: []domain.FallbackTrigger{domain.TriggerHTTP5xx},
					Budget:   domain.FallbackBudget{MaxAttempts: 3},
					Chain:    registrydomain.Registries{registryID},
				},
			},
			wantErr: registrydomain.ErrInvalidRegistryID,
		},
		{
			name: "model policies",
			input: appconsumer.CreateInput{
				ModelPolicies: domain.ModelPolicies{registryID: {Allowed: []string{"gpt-4o"}}},
			},
			wantErr: domain.ErrInvalidModelPolicy,
		},
		{
			name: "lb config members",
			input: appconsumer.CreateInput{
				LBConfig: &domain.LBConfig{
					Enabled: true,
					Members: []domain.LBPoolMember{{RegistryID: registryID, Models: []string{"gpt-4o"}}},
				},
				ModelPolicies: domain.ModelPolicies{registryID: {Allowed: []string{"gpt-4o"}}},
			},
			wantErr: domain.ErrInvalidModelPolicy,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			creator := appconsumer.NewCreator(repomocks.NewRepository(t), registrymocks.NewRepository(t), rolemocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
			tc.input.GatewayID = gwID
			tc.input.Name = "chat"
			tc.input.Type = domain.TypeLLM

			_, err := creator.Create(context.Background(), tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestCreator_Create_RejectsInvalidDomain(t *testing.T) {
	t.Parallel()
	creator := appconsumer.NewCreator(repomocks.NewRepository(t), registrymocks.NewRepository(t), rolemocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "",
		Type:      domain.TypeLLM,
	})
	if !errors.Is(err, domain.ErrInvalidName) {
		t.Fatalf("err = %v, want ErrInvalidName", err)
	}
}

func TestCreator_Create_RetriesOnSlugCollision(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(domain.ErrSlugAlreadyExists).Once()
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()

	creator := appconsumer.NewCreator(repo, registrymocks.NewRepository(t), rolemocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	c, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "chat",
		Type:      domain.TypeLLM,
	})
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if !domain.IsValidSlug(c.Slug) {
		t.Fatalf("Slug = %q, want regenerated valid slug", c.Slug)
	}
}

func TestCreator_Create_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(domain.ErrAlreadyExists).Once()

	creator := appconsumer.NewCreator(repo, registrymocks.NewRepository(t), rolemocks.NewRepository(t), newCacheManager(), cachetest.NoopPublisher(), newTestLogger())

	_, err := creator.Create(context.Background(), appconsumer.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "dupe",
		Type:      domain.TypeLLM,
	})
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}
