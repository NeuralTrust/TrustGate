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

func pathConsumer(t *testing.T, gatewayID ids.GatewayID, path string, authIDs ...ids.AuthID) *domain.Consumer {
	t.Helper()
	c, err := domain.New(domain.CreateParams{
		GatewayID: gatewayID,
		Name:      "c-" + path,
		Type:      domain.TypeMCP,
		Path:      path,
		AuthIDs:   authIDs,
	})
	require.NoError(t, err)
	c.Active = true
	return c
}

func pathAuth(t *testing.T, gatewayID ids.GatewayID) *authdomain.Auth {
	t.Helper()
	a, err := authdomain.NewAuth(gatewayID, "idp", authdomain.TypeOAuth2, true, authdomain.Config{
		OAuth2: &authdomain.OAuth2Config{Issuer: "https://idp.example.com", JWKSURL: "https://idp.example.com/jwks"},
	})
	require.NoError(t, err)
	return a
}

func TestPathResolver_MatchAcrossGateways(t *testing.T) {
	t.Parallel()
	gwA, gwB := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	authA, authB := pathAuth(t, gwA), pathAuth(t, gwB)
	consumerA := pathConsumer(t, gwA, "/v1/mcp/hub", authA.ID)
	consumerB := pathConsumer(t, gwB, "/v1/mcp/hub", authB.ID)

	consumers := consumermocks.NewRepository(t)
	consumers.EXPECT().FindActiveByPath(mock.Anything, "/v1/mcp/hub").
		Return([]*domain.Consumer{consumerA, consumerB}, nil).Once()
	auths := authmocks.NewRepository(t)
	auths.EXPECT().FindByIDs(mock.Anything, gwA, []ids.AuthID{authA.ID}).Return([]*authdomain.Auth{authA}, nil).Once()
	auths.EXPECT().FindByIDs(mock.Anything, gwB, []ids.AuthID{authB.ID}).Return([]*authdomain.Auth{authB}, nil).Once()
	gateways := gatewaymocks.NewRepository(t)

	resolver := appconsumer.NewPathResolver(consumers, auths, gateways, cache.NewTTLMapManager(time.Hour), newTestLogger())

	// Trailing slash and no host: canonicalized, both gateways match.
	matches, err := resolver.Match(context.Background(), "", "/v1/mcp/hub/")
	require.NoError(t, err)
	require.Len(t, matches, 2)
	require.Equal(t, gwA, matches[0].GatewayID)
	require.Equal(t, authA.ID, matches[0].Auths[0].ID)
	require.Equal(t, gwB, matches[1].GatewayID)

	// Second call is served from the cache (mocks expect a single call).
	matches, err = resolver.Match(context.Background(), "", "/v1/mcp/hub/")
	require.NoError(t, err)
	require.Len(t, matches, 2)
}

func TestPathResolver_HostFiltersToClaimingGateway(t *testing.T) {
	t.Parallel()
	gwA, gwB := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	authB := pathAuth(t, gwB)
	consumerA := pathConsumer(t, gwA, "/v1/mcp/hub")
	consumerB := pathConsumer(t, gwB, "/v1/mcp/hub", authB.ID)

	consumers := consumermocks.NewRepository(t)
	consumers.EXPECT().FindActiveByPath(mock.Anything, "/v1/mcp/hub").
		Return([]*domain.Consumer{consumerA, consumerB}, nil).Once()
	auths := authmocks.NewRepository(t)
	auths.EXPECT().FindByIDs(mock.Anything, gwB, []ids.AuthID{authB.ID}).Return([]*authdomain.Auth{authB}, nil).Once()
	gateways := gatewaymocks.NewRepository(t)
	gateways.EXPECT().FindByDomain(mock.Anything, "tenant-b.example.com").
		Return(&gatewaydomain.Gateway{ID: gwB, Name: "b", Domain: "tenant-b.example.com"}, nil).Once()

	resolver := appconsumer.NewPathResolver(consumers, auths, gateways, cache.NewTTLMapManager(time.Hour), newTestLogger())

	// Host carries a port and mixed case: normalized before the lookup.
	matches, err := resolver.Match(context.Background(), "Tenant-B.example.com:8082", "/v1/mcp/hub")
	require.NoError(t, err)
	require.Len(t, matches, 1)
	require.Equal(t, gwB, matches[0].GatewayID)
}

func TestPathResolver_UnclaimedHostKeepsAllCandidates(t *testing.T) {
	t.Parallel()
	gwA := ids.New[ids.GatewayKind]()
	consumerA := pathConsumer(t, gwA, "/v1/mcp/hub")

	consumers := consumermocks.NewRepository(t)
	consumers.EXPECT().FindActiveByPath(mock.Anything, "/v1/mcp/hub").
		Return([]*domain.Consumer{consumerA}, nil).Once()
	auths := authmocks.NewRepository(t)
	gateways := gatewaymocks.NewRepository(t)
	gateways.EXPECT().FindByDomain(mock.Anything, "localhost").
		Return(nil, gatewaydomain.ErrNotFound).Once()

	resolver := appconsumer.NewPathResolver(consumers, auths, gateways, cache.NewTTLMapManager(time.Hour), newTestLogger())

	matches, err := resolver.Match(context.Background(), "localhost:8082", "/v1/mcp/hub")
	require.NoError(t, err)
	require.Len(t, matches, 1)
}

func TestPathResolver_NoMatch(t *testing.T) {
	t.Parallel()
	consumers := consumermocks.NewRepository(t)
	consumers.EXPECT().FindActiveByPath(mock.Anything, "/nope").Return(nil, nil).Once()

	resolver := appconsumer.NewPathResolver(
		consumers, authmocks.NewRepository(t), gatewaymocks.NewRepository(t),
		cache.NewTTLMapManager(time.Hour), newTestLogger(),
	)
	matches, err := resolver.Match(context.Background(), "", "/nope")
	require.NoError(t, err)
	require.Empty(t, matches)
}
