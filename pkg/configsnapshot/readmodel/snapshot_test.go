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

package readmodel_test

import (
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/configsnapshot/readmodel"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var baseTime = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

func TestGatewayIndexing(t *testing.T) {
	t.Parallel()
	gw := gatewaydomain.Gateway{
		ID:        ids.New[ids.GatewayKind](),
		Slug:      "acme-gateway",
		Status:    "active",
		Domain:    "acme.example.com",
		CreatedAt: baseTime,
	}
	snap := readmodel.Build(readmodel.Data{Gateways: []gatewaydomain.Gateway{gw}})

	got, ok := snap.GatewayByID(gw.ID)
	require.True(t, ok)
	assert.Equal(t, gw.ID, got.ID)

	got, ok = snap.GatewayBySlug("ACME-Gateway")
	require.True(t, ok, "slug lookup must normalize case and whitespace")
	assert.Equal(t, gw.ID, got.ID)

	got, ok = snap.GatewayByDomain("acme.example.com")
	require.True(t, ok)
	assert.Equal(t, gw.ID, got.ID)

	_, ok = snap.GatewayByDomain("")
	assert.False(t, ok, "empty host must never match a gateway")

	_, ok = snap.GatewayBySlug("missing")
	assert.False(t, ok)
}

func TestConsumerActiveBySlugAndGrouping(t *testing.T) {
	t.Parallel()
	gwA := ids.New[ids.GatewayKind]()
	gwB := ids.New[ids.GatewayKind]()
	authID := ids.New[ids.AuthKind]()

	c1 := consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gwA, Slug: "alpha", Active: true, AuthIDs: []ids.AuthID{authID}, CreatedAt: baseTime}
	c2 := consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gwA, Slug: "beta", Active: false, CreatedAt: baseTime.Add(time.Hour)}
	c3 := consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gwB, Slug: "gamma", Active: true, AuthIDs: []ids.AuthID{authID}, CreatedAt: baseTime.Add(2 * time.Hour)}

	snap := readmodel.Build(readmodel.Data{Consumers: []consumerdomain.Consumer{c1, c2, c3}})

	active, ok := snap.ConsumerActiveBySlug("alpha")
	require.True(t, ok)
	assert.Equal(t, c1.ID, active.ID)

	_, ok = snap.ConsumerActiveBySlug("beta")
	assert.False(t, ok, "inactive consumers are not indexed by active slug")

	assert.Len(t, snap.ConsumersByGateway(gwA), 2)
	assert.Len(t, snap.ConsumersByGateway(gwB), 1)

	byAuth := snap.ConsumersByAuthID(authID)
	require.Len(t, byAuth, 2)
	assert.Equal(t, c3.ID, byAuth[0].ID, "created_at DESC ordering: newest first")
	assert.Equal(t, c1.ID, byAuth[1].ID)
}

func TestAuthByAPIKeyHashOnlyEnabledKeys(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	enabledKey := authdomain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: gw, Type: authdomain.TypeAPIKey, Enabled: true, KeyHash: "hash-enabled", CreatedAt: baseTime}
	disabledKey := authdomain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: gw, Type: authdomain.TypeAPIKey, Enabled: false, KeyHash: "hash-disabled", CreatedAt: baseTime}
	oidc := authdomain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: gw, Type: authdomain.TypeOIDC, Enabled: true, CreatedAt: baseTime}

	snap := readmodel.Build(readmodel.Data{Auths: []authdomain.Auth{enabledKey, disabledKey, oidc}})

	got, ok := snap.AuthByAPIKeyHash("hash-enabled")
	require.True(t, ok)
	assert.Equal(t, enabledKey.ID, got.ID)

	_, ok = snap.AuthByAPIKeyHash("hash-disabled")
	assert.False(t, ok, "disabled api keys must not be indexed")
}

func TestAuthEnabledOrderings(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	older := authdomain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: gw, Type: authdomain.TypeOIDC, Enabled: true, CreatedAt: baseTime}
	newer := authdomain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: gw, Type: authdomain.TypeOIDC, Enabled: true, CreatedAt: baseTime.Add(time.Hour)}
	disabled := authdomain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: gw, Type: authdomain.TypeOIDC, Enabled: false, CreatedAt: baseTime.Add(2 * time.Hour)}

	snap := readmodel.Build(readmodel.Data{Auths: []authdomain.Auth{newer, older, disabled}})

	byTypes := snap.AuthsEnabledByTypes([]authdomain.Type{authdomain.TypeOIDC})
	require.Len(t, byTypes, 2, "disabled auths excluded")
	assert.Equal(t, older.ID, byTypes[0].ID, "FindEnabledByTypes is created_at ASC")
	assert.Equal(t, newer.ID, byTypes[1].ID)

	byGateway := snap.AuthsEnabledByGatewayAndType(gw, authdomain.TypeOIDC)
	require.Len(t, byGateway, 2)
	assert.Equal(t, newer.ID, byGateway[0].ID, "ListEnabledByGatewayAndType is created_at DESC")
	assert.Equal(t, older.ID, byGateway[1].ID)

	assert.Empty(t, snap.AuthsEnabledByTypes(nil))
}

func TestPolicyOrderingByPriority(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	p1 := policydomain.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gw, Priority: 10, CreatedAt: baseTime}
	p2 := policydomain.Policy{ID: ids.New[ids.PolicyKind](), GatewayID: gw, Priority: 1, CreatedAt: baseTime.Add(time.Hour)}

	snap := readmodel.Build(readmodel.Data{Policies: []policydomain.Policy{p1, p2}})

	ordered := snap.PoliciesByGateway(gw)
	require.Len(t, ordered, 2)
	assert.Equal(t, p2.ID, ordered[0].ID, "lower priority first")
	assert.Equal(t, p1.ID, ordered[1].ID)

	scoped := snap.PoliciesByIDs(gw, []ids.PolicyID{p1.ID})
	require.Len(t, scoped, 1)
	assert.Equal(t, p1.ID, scoped[0].ID)

	other := ids.New[ids.GatewayKind]()
	assert.Empty(t, snap.PoliciesByIDs(other, []ids.PolicyID{p1.ID}), "cross-gateway scope denies")
}

func TestRoleOrderingAndScope(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	r1 := roledomain.Role{ID: ids.New[ids.RoleKind](), GatewayID: gw, Name: "a", CreatedAt: baseTime}
	r2 := roledomain.Role{ID: ids.New[ids.RoleKind](), GatewayID: gw, Name: "b", CreatedAt: baseTime.Add(time.Hour)}

	snap := readmodel.Build(readmodel.Data{Roles: []roledomain.Role{r1, r2}})

	ordered := snap.RolesByGateway(gw)
	require.Len(t, ordered, 2)
	assert.Equal(t, r2.ID, ordered[0].ID, "created_at DESC ordering")
	assert.Equal(t, r1.ID, ordered[1].ID)
}

func TestCatalogKeying(t *testing.T) {
	t.Parallel()
	models := []readmodel.CatalogModel{
		{ProviderCode: "openai", Model: catalogdomain.Model{Slug: "gpt-4", DisplayName: "GPT-4", InputPrice: "1.5"}},
		{ProviderCode: "openai", Model: catalogdomain.Model{Slug: "gpt-3", DisplayName: "GPT-3"}},
		{ProviderCode: "anthropic", Model: catalogdomain.Model{Slug: "claude", DisplayName: "Claude"}},
	}
	providers := []catalogdomain.Provider{{Code: "openai"}, {Code: "anthropic"}}
	snap := readmodel.Build(readmodel.Data{Providers: providers, CatalogModels: models})

	m, ok := snap.CatalogModelByProviderSlug("openai", "gpt-4")
	require.True(t, ok)
	assert.Equal(t, "GPT-4", m.DisplayName)

	_, ok = snap.CatalogModelByProviderSlug("anthropic", "gpt-4")
	assert.False(t, ok, "provider code is part of the key")

	byProvider := snap.CatalogModelsByProviderCode("openai")
	require.Len(t, byProvider, 2)
	assert.Equal(t, "gpt-3", byProvider[0].Slug, "models sorted by slug")
	assert.Equal(t, "gpt-4", byProvider[1].Slug)

	all := snap.CatalogModelsByProviderCode("")
	assert.Len(t, all, 3, "empty provider code returns all models")

	assert.Len(t, snap.Providers(), 2)
}
