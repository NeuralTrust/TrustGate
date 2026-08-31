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
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	authmocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	consumermocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	gatewaymocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func slugConsumer(t *testing.T, gatewayID ids.GatewayID, slug string, authIDs ...ids.AuthID) *domain.Consumer {
	t.Helper()
	c, err := domain.New(domain.CreateParams{
		GatewayID: gatewayID,
		Name:      "c-" + slug,
		Type:      domain.TypeMCP,
		AuthIDs:   authIDs,
	})
	require.NoError(t, err)
	c.Slug = slug
	c.Active = true
	return c
}

func pathAuth(t *testing.T, gatewayID ids.GatewayID) *authdomain.Auth {
	t.Helper()
	a, err := authdomain.NewAuth(gatewayID, "idp", authdomain.TypeOAuth2, true, authdomain.Config{
		OAuth2: &authdomain.OAuth2Config{
			Issuer:    "https://idp.example.com",
			JWKSURL:   "https://idp.example.com/jwks",
			Audiences: []string{"trustgate"},
		},
	})
	require.NoError(t, err)
	return a
}

func TestPathResolver_MatchBySlugAndCaches(t *testing.T) {
	t.Parallel()
	gwA := ids.New[ids.GatewayKind]()
	authA := pathAuth(t, gwA)
	consumerA := slugConsumer(t, gwA, "hub", authA.ID)

	consumers := consumermocks.NewRepository(t)
	consumers.EXPECT().FindActiveBySlug(mock.Anything, "hub").
		Return(consumerA, nil).Once()
	auths := authmocks.NewRepository(t)
	auths.EXPECT().FindByIDs(mock.Anything, gwA, []ids.AuthID{authA.ID}).Return([]*authdomain.Auth{authA}, nil).Once()
	gateways := gatewaymocks.NewRepository(t)

	resolver := appconsumer.NewPathResolver(consumers, auths, gateways, cache.NewTTLMapManager(time.Hour), newTestLogger())

	matches, err := resolver.Match(context.Background(), "", "/hub/mcp")
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.Equal(t, gwA, matches[0].GatewayID)
	require.Equal(t, authA.ID, matches[0].Auths[0].ID)

	matches, err = resolver.Match(context.Background(), "", "/hub/mcp")
	require.NoError(t, err)
	require.Len(t, matches, 1)
}

func TestPathResolver_HostFiltersToClaimingGateway(t *testing.T) {
	t.Parallel()
	gwB := ids.New[ids.GatewayKind]()
	authB := pathAuth(t, gwB)
	consumerB := slugConsumer(t, gwB, "hub", authB.ID)

	consumers := consumermocks.NewRepository(t)
	consumers.EXPECT().FindActiveBySlug(mock.Anything, "hub").
		Return(consumerB, nil).Once()
	auths := authmocks.NewRepository(t)
	auths.EXPECT().FindByIDs(mock.Anything, gwB, []ids.AuthID{authB.ID}).Return([]*authdomain.Auth{authB}, nil).Once()
	gateways := gatewaymocks.NewRepository(t)
	gateways.EXPECT().FindByDomain(mock.Anything, "tenant-b.example.com").
		Return(&gatewaydomain.Gateway{ID: gwB, Slug: "b", Domain: "tenant-b.example.com"}, nil).Once()

	resolver := appconsumer.NewPathResolver(consumers, auths, gateways, cache.NewTTLMapManager(time.Hour), newTestLogger())

	matches, err := resolver.Match(context.Background(), "Tenant-B.example.com:8082", "/hub/mcp")
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.Equal(t, gwB, matches[0].GatewayID)
}

func TestPathResolver_HostClaimedByOtherGatewayDropsConsumer(t *testing.T) {
	t.Parallel()
	gwA, gwB := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	consumerA := slugConsumer(t, gwA, "hub")

	consumers := consumermocks.NewRepository(t)
	consumers.EXPECT().FindActiveBySlug(mock.Anything, "hub").
		Return(consumerA, nil).Once()
	auths := authmocks.NewRepository(t)
	gateways := gatewaymocks.NewRepository(t)
	gateways.EXPECT().FindByDomain(mock.Anything, "tenant-b.example.com").
		Return(&gatewaydomain.Gateway{ID: gwB, Slug: "b", Domain: "tenant-b.example.com"}, nil).Once()

	resolver := appconsumer.NewPathResolver(consumers, auths, gateways, cache.NewTTLMapManager(time.Hour), newTestLogger())

	matches, err := resolver.Match(context.Background(), "tenant-b.example.com", "/hub/mcp")
	require.NoError(t, err)
	require.Empty(t, matches)
}

func TestPathResolver_UnclaimedHostKeepsDomainlessGateways(t *testing.T) {
	t.Parallel()
	gwA := ids.New[ids.GatewayKind]()
	consumerA := slugConsumer(t, gwA, "hub")

	consumers := consumermocks.NewRepository(t)
	consumers.EXPECT().FindActiveBySlug(mock.Anything, "hub").
		Return(consumerA, nil).Once()
	auths := authmocks.NewRepository(t)
	gateways := gatewaymocks.NewRepository(t)
	gateways.EXPECT().FindByDomain(mock.Anything, "localhost").
		Return(nil, gatewaydomain.ErrNotFound).Once()
	gateways.EXPECT().FindByID(mock.Anything, gwA).
		Return(&gatewaydomain.Gateway{ID: gwA, Slug: "a"}, nil).Once()

	resolver := appconsumer.NewPathResolver(consumers, auths, gateways, cache.NewTTLMapManager(time.Hour), newTestLogger())

	matches, err := resolver.Match(context.Background(), "localhost:8082", "/hub/mcp")
	require.NoError(t, err)
	require.Len(t, matches, 1)
}

func TestPathResolver_UnclaimedHostDropsDomainClaimingGateways(t *testing.T) {
	t.Parallel()
	gwA := ids.New[ids.GatewayKind]()
	consumerA := slugConsumer(t, gwA, "hub")

	consumers := consumermocks.NewRepository(t)
	consumers.EXPECT().FindActiveBySlug(mock.Anything, "hub").
		Return(consumerA, nil).Once()
	auths := authmocks.NewRepository(t)
	gateways := gatewaymocks.NewRepository(t)
	gateways.EXPECT().FindByDomain(mock.Anything, "evil.example.com").
		Return(nil, gatewaydomain.ErrNotFound).Once()
	gateways.EXPECT().FindByID(mock.Anything, gwA).
		Return(&gatewaydomain.Gateway{ID: gwA, Slug: "a", Domain: "tenant-a.example.com"}, nil).Once()

	resolver := appconsumer.NewPathResolver(consumers, auths, gateways, cache.NewTTLMapManager(time.Hour), newTestLogger())

	matches, err := resolver.Match(context.Background(), "evil.example.com", "/hub/mcp")
	require.NoError(t, err)
	require.Empty(t, matches)
}

func TestPathResolver_NoMatch(t *testing.T) {
	t.Parallel()
	consumers := consumermocks.NewRepository(t)
	consumers.EXPECT().FindActiveBySlug(mock.Anything, "nope").Return(nil, domain.ErrNotFound).Once()

	resolver := appconsumer.NewPathResolver(
		consumers, authmocks.NewRepository(t), gatewaymocks.NewRepository(t),
		cache.NewTTLMapManager(time.Hour), newTestLogger(),
	)
	matches, err := resolver.Match(context.Background(), "", "/nope/mcp")
	require.NoError(t, err)
	require.Empty(t, matches)
}

func TestPathResolver_NonMCPPathReturnsNoMatch(t *testing.T) {
	t.Parallel()
	resolver := appconsumer.NewPathResolver(
		consumermocks.NewRepository(t), authmocks.NewRepository(t), gatewaymocks.NewRepository(t),
		cache.NewTTLMapManager(time.Hour), newTestLogger(),
	)
	matches, err := resolver.Match(context.Background(), "", "/v1/chat/completions")
	require.NoError(t, err)
	require.Empty(t, matches)
}
