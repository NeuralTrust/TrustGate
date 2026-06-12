package consumer_test

import (
	"context"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	authmocks "github.com/NeuralTrust/AgentGateway/pkg/domain/auth/mocks"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	consumermocks "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer/mocks"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	gatewaymocks "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
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
			Audiences: []string{"agentgateway"},
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
		Return(&gatewaydomain.Gateway{ID: gwB, Name: "b", Domain: "tenant-b.example.com"}, nil).Once()

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
		Return(&gatewaydomain.Gateway{ID: gwB, Name: "b", Domain: "tenant-b.example.com"}, nil).Once()

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
		Return(&gatewaydomain.Gateway{ID: gwA, Name: "a"}, nil).Once()

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
		Return(&gatewaydomain.Gateway{ID: gwA, Name: "a", Domain: "tenant-a.example.com"}, nil).Once()

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
