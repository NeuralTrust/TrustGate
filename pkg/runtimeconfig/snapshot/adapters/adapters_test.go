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

package adapters_test

import (
	"context"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/adapters"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var baseTime = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

type fixture struct {
	store   *configsync.MemoryStore[*readmodel.Snapshot]
	gateway gatewaydomain.Gateway
	other   ids.GatewayID
	reg     registrydomain.Registry
	auth    authdomain.Auth
	policy  policydomain.Policy
	role    roledomain.Role
}

func newFixture() fixture {
	gwID := ids.New[ids.GatewayKind]()
	otherGW := ids.New[ids.GatewayKind]()
	gw := gatewaydomain.Gateway{
		ID:        gwID,
		Slug:      "gw-one",
		Status:    "active",
		Domain:    "one.example.com",
		Metadata:  map[string]string{"tenant_id": "team-1"},
		CreatedAt: baseTime,
	}
	reg := registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		GatewayID: gwID,
		Name:      "openai",
		Type:      registrydomain.TypeLLM,
		Enabled:   true,
		LLMTarget: &registrydomain.LLMTarget{
			Provider: "openai",
			Auth:     registrydomain.NewAPIKeyAuth("sk-secret-value"),
		},
		CreatedAt: baseTime,
	}
	auth := authdomain.Auth{
		ID:        ids.New[ids.AuthKind](),
		GatewayID: gwID,
		Type:      authdomain.TypeAPIKey,
		Enabled:   true,
		KeyHash:   "key-hash-1",
		CreatedAt: baseTime,
	}
	pol := policydomain.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gwID, Priority: 1, CreatedAt: baseTime}
	rl := roledomain.Role{ID: ids.New[ids.RoleKind](), GatewayID: gwID, Name: "role", CreatedAt: baseTime}
	con := consumerdomain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gwID, Slug: "consumer-one", Active: true,
		AuthIDs: []ids.AuthID{auth.ID}, CreatedAt: baseTime,
	}

	snap := readmodel.Build(readmodel.Data{
		Gateways:   []gatewaydomain.Gateway{gw},
		Consumers:  []consumerdomain.Consumer{con},
		Registries: []registrydomain.Registry{reg},
		Policies:   []policydomain.Policy{pol},
		Auths:      []authdomain.Auth{auth},
		Roles:      []roledomain.Role{rl},
	})
	store := configsync.NewMemoryStore[*readmodel.Snapshot]()
	store.Swap(&configsync.Versioned[*readmodel.Snapshot]{Version: "v1", Snapshot: snap})

	return fixture{store: store, gateway: gw, other: otherGW, reg: reg, auth: auth, policy: pol, role: rl}
}

func emptyStore() *configsync.MemoryStore[*readmodel.Snapshot] {
	return configsync.NewMemoryStore[*readmodel.Snapshot]()
}

func TestGatewayAdapterReads(t *testing.T) {
	t.Parallel()
	f := newFixture()
	repo := adapters.NewGatewayRepository(f.store)
	ctx := context.Background()

	got, err := repo.FindBySlug(ctx, "GW-One")
	require.NoError(t, err)
	assert.Equal(t, f.gateway.ID, got.ID)

	got, err = repo.FindByID(ctx, f.gateway.ID)
	require.NoError(t, err)
	assert.Equal(t, f.gateway.ID, got.ID)

	got.Metadata["tenant_id"] = "mutated"
	fresh, err := repo.FindByID(ctx, f.gateway.ID)
	require.NoError(t, err)
	assert.Equal(t, "team-1", fresh.Metadata["tenant_id"], "returned gateway must be a deep clone")

	_, err = repo.FindByDomain(ctx, "unknown.example.com")
	assert.ErrorIs(t, err, gatewaydomain.ErrNotFound)
}

func TestGatewayAdapterNotReadyAndReadOnly(t *testing.T) {
	t.Parallel()
	repo := adapters.NewGatewayRepository(emptyStore())
	ctx := context.Background()

	_, err := repo.FindByID(ctx, ids.New[ids.GatewayKind]())
	assert.ErrorIs(t, err, gatewaydomain.ErrNotFound)

	assert.ErrorIs(t, repo.Save(ctx, &gatewaydomain.Gateway{}), configsync.ErrReadOnly)
	assert.ErrorIs(t, repo.Update(ctx, &gatewaydomain.Gateway{}), configsync.ErrReadOnly)
	assert.ErrorIs(t, repo.Delete(ctx, ids.New[ids.GatewayKind]()), configsync.ErrReadOnly)
	_, _, err = repo.List(ctx, gatewaydomain.ListFilter{})
	assert.ErrorIs(t, err, configsync.ErrReadOnly)
}

func TestConsumerAdapter(t *testing.T) {
	t.Parallel()
	f := newFixture()
	repo := adapters.NewConsumerRepository(f.store)
	ctx := context.Background()

	got, err := repo.FindActiveBySlug(ctx, "consumer-one")
	require.NoError(t, err)
	assert.Equal(t, "consumer-one", got.Slug)

	got.AuthIDs[0] = ids.New[ids.AuthKind]()
	fresh, err := repo.FindActiveBySlug(ctx, "consumer-one")
	require.NoError(t, err)
	assert.Equal(t, f.auth.ID, fresh.AuthIDs[0], "mutating a returned consumer must not affect the snapshot")

	byGateway, err := repo.ListByGateway(ctx, f.gateway.ID)
	require.NoError(t, err)
	assert.Len(t, byGateway, 1)

	byAuth, err := repo.ListByAuthID(ctx, f.auth.ID)
	require.NoError(t, err)
	assert.Len(t, byAuth, 1)

	assert.ErrorIs(t, repo.Save(ctx, &consumerdomain.Consumer{}), configsync.ErrReadOnly)
	assert.ErrorIs(t, repo.Update(ctx, &consumerdomain.Consumer{}), configsync.ErrReadOnly)
	assert.ErrorIs(t, repo.Delete(ctx, f.gateway.ID, ids.New[ids.ConsumerKind]()), configsync.ErrReadOnly)
	assert.ErrorIs(t, repo.AttachAuth(ctx, ids.New[ids.ConsumerKind](), f.auth.ID), configsync.ErrReadOnly)
	assert.ErrorIs(t, repo.DetachAuth(ctx, ids.New[ids.ConsumerKind](), f.auth.ID), configsync.ErrReadOnly)
	_, err = repo.DetachRegistryIfUnreferenced(ctx, f.gateway.ID, ids.New[ids.ConsumerKind](), ids.New[ids.RegistryKind]())
	assert.ErrorIs(t, err, configsync.ErrReadOnly)
}

func TestRegistryAdapterScopingAndSecrets(t *testing.T) {
	t.Parallel()
	f := newFixture()
	repo := adapters.NewRegistryRepository(f.store)
	ctx := context.Background()

	got, err := repo.FindByID(ctx, f.reg.ID)
	require.NoError(t, err)
	require.NotNil(t, got.LLMTarget)
	require.NotNil(t, got.LLMTarget.Auth)
	require.NotNil(t, got.LLMTarget.Auth.APIKey)
	assert.Equal(t, "sk-secret-value", got.LLMTarget.Auth.APIKey.APIKey, "decrypted credentials survive the snapshot")

	inScope, err := repo.FindByIDs(ctx, f.gateway.ID, []ids.RegistryID{f.reg.ID})
	require.NoError(t, err)
	assert.Len(t, inScope, 1)

	crossGateway, err := repo.FindByIDs(ctx, f.other, []ids.RegistryID{f.reg.ID})
	require.NoError(t, err)
	assert.Empty(t, crossGateway, "registries are scoped to their gateway")

	empty, err := repo.FindByIDs(ctx, f.gateway.ID, nil)
	require.NoError(t, err)
	assert.Nil(t, empty)

	assert.ErrorIs(t, repo.Save(ctx, &registrydomain.Registry{}), configsync.ErrReadOnly)
	assert.ErrorIs(t, repo.Delete(ctx, f.gateway.ID, f.reg.ID), configsync.ErrReadOnly)
}

func TestPolicyAdapter(t *testing.T) {
	t.Parallel()
	f := newFixture()
	repo := adapters.NewPolicyRepository(f.store)
	ctx := context.Background()

	got, err := repo.FindByID(ctx, f.policy.ID)
	require.NoError(t, err)
	assert.Equal(t, f.policy.ID, got.ID)

	byGateway, err := repo.ListByGateway(ctx, f.gateway.ID)
	require.NoError(t, err)
	assert.Len(t, byGateway, 1)

	crossGateway, err := repo.FindByIDs(ctx, f.other, []ids.PolicyID{f.policy.ID})
	require.NoError(t, err)
	assert.Empty(t, crossGateway)

	assert.ErrorIs(t, repo.SetGlobal(ctx, f.gateway.ID, f.policy.ID, true), configsync.ErrReadOnly)
	assert.ErrorIs(t, repo.Save(ctx, &policydomain.Policy{}), configsync.ErrReadOnly)
}

func TestAuthAdapter(t *testing.T) {
	t.Parallel()
	f := newFixture()
	repo := adapters.NewAuthRepository(f.store)
	ctx := context.Background()

	got, err := repo.FindByAPIKeyHash(ctx, "key-hash-1")
	require.NoError(t, err)
	assert.Equal(t, f.auth.ID, got.ID)
	assert.Equal(t, "key-hash-1", got.KeyHash, "KeyHash is carried through the snapshot")

	_, err = repo.FindByAPIKeyHash(ctx, "missing")
	assert.ErrorIs(t, err, authdomain.ErrNotFound)

	inScope, err := repo.FindByIDs(ctx, f.gateway.ID, []ids.AuthID{f.auth.ID})
	require.NoError(t, err)
	require.Len(t, inScope, 1)
	assert.Equal(t, "key-hash-1", inScope[0].KeyHash)

	crossGateway, err := repo.FindByIDs(ctx, f.other, []ids.AuthID{f.auth.ID})
	require.NoError(t, err)
	assert.Empty(t, crossGateway)

	assert.ErrorIs(t, repo.Save(ctx, &authdomain.Auth{}), configsync.ErrReadOnly)
	assert.ErrorIs(t, repo.Delete(ctx, f.gateway.ID, f.auth.ID), configsync.ErrReadOnly)
}

func TestRoleAdapter(t *testing.T) {
	t.Parallel()
	f := newFixture()
	repo := adapters.NewRoleRepository(f.store)
	ctx := context.Background()

	got, err := repo.FindByID(ctx, f.role.ID)
	require.NoError(t, err)
	assert.Equal(t, f.role.ID, got.ID)

	byGateway, err := repo.ListByGateway(ctx, f.gateway.ID)
	require.NoError(t, err)
	assert.Len(t, byGateway, 1)

	crossGateway, err := repo.FindByIDs(ctx, f.other, []ids.RoleID{f.role.ID})
	require.NoError(t, err)
	assert.Empty(t, crossGateway)

	assert.ErrorIs(t, repo.Save(ctx, &roledomain.Role{}), configsync.ErrReadOnly)
	assert.ErrorIs(t, repo.AttachRegistry(ctx, f.role.ID, ids.New[ids.RegistryKind]()), configsync.ErrReadOnly)
	_, err = repo.DetachRegistryIfUnreferenced(ctx, f.gateway.ID, f.role.ID, ids.New[ids.RegistryKind]())
	assert.ErrorIs(t, err, configsync.ErrReadOnly)
}

func TestCatalogAdapter(t *testing.T) {
	t.Parallel()
	models := []readmodel.CatalogModel{
		{ProviderCode: "openai", Model: catalogdomain.Model{Slug: "gpt-4", DisplayName: "GPT-4", InputPrice: "1.5", OutputPrice: "3.0"}},
	}
	snap := readmodel.Build(readmodel.Data{
		Providers:     []catalogdomain.Provider{{Code: "openai"}},
		CatalogModels: models,
	})
	store := configsync.NewMemoryStore[*readmodel.Snapshot]()
	store.Swap(&configsync.Versioned[*readmodel.Snapshot]{Version: "v1", Snapshot: snap})
	repo := adapters.NewCatalogRepository(store)
	ctx := context.Background()

	got, err := repo.FindModel(ctx, "openai", "gpt-4")
	require.NoError(t, err)
	assert.Equal(t, "GPT-4", got.DisplayName)

	_, err = repo.FindModel(ctx, "openai", "missing")
	assert.ErrorIs(t, err, commonerrors.ErrNotFound)

	all, err := repo.ListModelsByProviderCode(ctx, "")
	require.NoError(t, err)
	assert.Len(t, all, 1)

	providers, err := repo.ListProviders(ctx)
	require.NoError(t, err)
	assert.Len(t, providers, 1)

	assert.ErrorIs(t, repo.UpsertModel(ctx, &catalogdomain.Model{}), configsync.ErrReadOnly)
	assert.ErrorIs(t, repo.UpsertProvider(ctx, &catalogdomain.Provider{}), configsync.ErrReadOnly)
	assert.ErrorIs(t, repo.DisableModelsExcept(ctx, ids.New[ids.ProviderKind](), "source", nil), configsync.ErrReadOnly)
}

func TestCatalogNotReady(t *testing.T) {
	t.Parallel()
	repo := adapters.NewCatalogRepository(emptyStore())
	_, err := repo.FindModel(context.Background(), "openai", "gpt-4")
	assert.ErrorIs(t, err, commonerrors.ErrNotFound)
}
