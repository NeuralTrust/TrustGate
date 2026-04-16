package upstream

import (
	"context"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	gatewayMocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	upstreamMocks "github.com/NeuralTrust/TrustGate/pkg/domain/upstream/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	cacheMocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	gcpMocks "github.com/NeuralTrust/TrustGate/pkg/infra/auth/gcp/mocks"
	appMocks "github.com/NeuralTrust/TrustGate/pkg/app/upstream/mocks"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupCreator(t *testing.T) (
	Creator,
	*upstreamMocks.Repository,
	*gatewayMocks.Repository,
	*cacheMocks.Client,
	*appMocks.DescriptionEmbeddingCreator,
	*gcpMocks.ServiceAccountService,
) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	repo := upstreamMocks.NewRepository(t)
	gatewayRepo := gatewayMocks.NewRepository(t)
	cache := cacheMocks.NewClient(t)
	descEmb := appMocks.NewDescriptionEmbeddingCreator(t)
	saService := gcpMocks.NewServiceAccountService(t)

	c := NewCreator(logger, repo, gatewayRepo, cache, descEmb, saService)
	return c, repo, gatewayRepo, cache, descEmb, saService
}

func validUpstreamRequest() *request.UpstreamRequest {
	return &request.UpstreamRequest{
		Name:      "test-upstream",
		Algorithm: "round-robin",
		Targets: []request.TargetRequest{
			{
				ID:       "t1",
				Host:     "api.example.com",
				Port:     443,
				Protocol: "https",
				Weight:   100,
			},
		},
	}
}

func TestCreator_Create_Success(t *testing.T) {
	c, repo, gatewayRepo, cache, descEmb, _ := setupCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()

	gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	repo.EXPECT().CreateUpstream(ctx, mock.AnythingOfType("*upstream.Upstream")).Return(nil)
	cache.EXPECT().SaveUpstream(ctx, gatewayID.String(), mock.AnythingOfType("*upstream.Upstream")).Return(nil)
	descEmb.EXPECT().Process(ctx, mock.AnythingOfType("*upstream.Upstream")).Return(nil)

	result, err := c.Create(ctx, gatewayID, validUpstreamRequest())

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test-upstream", result.Name)
	assert.Equal(t, "round-robin", result.Algorithm)
	assert.Equal(t, gatewayID, result.GatewayID)
	assert.NotEqual(t, uuid.Nil, result.ID)
	assert.Len(t, result.Targets, 1)
}

func TestCreator_Create_GatewayNotFound(t *testing.T) {
	c, _, gatewayRepo, _, _, _ := setupCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()

	gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(nil, errors.New("not found"))

	result, err := c.Create(ctx, gatewayID, validUpstreamRequest())

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrGatewayNotFound)
}

func TestCreator_Create_InvalidEmbeddingProvider(t *testing.T) {
	c, _, _, _, _, _ := setupCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()

	req := validUpstreamRequest()
	req.Embedding = &request.EmbeddingRequest{Provider: "invalid-provider", Model: "model"}

	result, err := c.Create(ctx, gatewayID, req)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrInvalidEmbeddingProvider)
}

func TestCreator_Create_RepositoryError(t *testing.T) {
	c, repo, gatewayRepo, _, _, _ := setupCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()

	gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	repo.EXPECT().CreateUpstream(ctx, mock.Anything).Return(errors.New("db error"))

	result, err := c.Create(ctx, gatewayID, validUpstreamRequest())

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create upstream")
}

func TestCreator_Create_CacheFails_StillReturns(t *testing.T) {
	c, repo, gatewayRepo, cache, descEmb, _ := setupCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()

	gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	repo.EXPECT().CreateUpstream(ctx, mock.Anything).Return(nil)
	cache.EXPECT().SaveUpstream(ctx, mock.Anything, mock.Anything).Return(errors.New("cache error"))
	descEmb.EXPECT().Process(ctx, mock.Anything).Return(nil)

	result, err := c.Create(ctx, gatewayID, validUpstreamRequest())

	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestCreator_Create_WithProxy(t *testing.T) {
	c, repo, gatewayRepo, cache, descEmb, _ := setupCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()

	gatewayRepo.EXPECT().Get(ctx, gatewayID).Return(&domainGateway.Gateway{ID: gatewayID}, nil)
	repo.EXPECT().CreateUpstream(ctx, mock.MatchedBy(func(u *upstream.Upstream) bool {
		return u.Proxy != nil && u.Proxy.Protocol == "http"
	})).Return(nil)
	cache.EXPECT().SaveUpstream(ctx, mock.Anything, mock.Anything).Return(nil)
	descEmb.EXPECT().Process(ctx, mock.Anything).Return(nil)

	req := validUpstreamRequest()
	req.ProxyConfig = &request.ProxyConfigRequest{Host: "proxy.example.com", Port: "8080"}

	result, err := c.Create(ctx, gatewayID, req)

	require.NoError(t, err)
	assert.NotNil(t, result.Proxy)
	assert.Equal(t, "http", result.Proxy.Protocol)
}
