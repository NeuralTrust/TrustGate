package upstream

import (
	"context"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	upstreamMocks "github.com/NeuralTrust/TrustGate/pkg/domain/upstream/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	gcpMocks "github.com/NeuralTrust/TrustGate/pkg/infra/auth/gcp/mocks"
	cacheMocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	appMocks "github.com/NeuralTrust/TrustGate/pkg/app/upstream/mocks"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupUpdater(t *testing.T) (
	Updater,
	*upstreamMocks.Repository,
	*cacheMocks.EventPublisher,
	*cacheMocks.Client,
	*appMocks.DescriptionEmbeddingCreator,
	*gcpMocks.ServiceAccountService,
) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	repo := upstreamMocks.NewRepository(t)
	publisher := cacheMocks.NewEventPublisher(t)
	cache := cacheMocks.NewClient(t)
	descEmb := appMocks.NewDescriptionEmbeddingCreator(t)
	saService := gcpMocks.NewServiceAccountService(t)

	u := NewUpdater(logger, repo, publisher, cache, descEmb, saService)
	return u, repo, publisher, cache, descEmb, saService
}

func TestUpdater_Update_Success(t *testing.T) {
	u, repo, publisher, cache, descEmb, _ := setupUpdater(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	upstreamID := uuid.New()

	existing := &upstream.Upstream{
		ID:        upstreamID,
		GatewayID: gatewayID,
		Name:      "old-name",
		Algorithm: "round-robin",
		Targets:   upstream.Targets{},
	}

	updated := &upstream.Upstream{
		ID:        upstreamID,
		GatewayID: gatewayID,
		Name:      "test-upstream",
		Algorithm: "round-robin",
	}

	repo.EXPECT().GetUpstream(ctx, upstreamID).Return(existing, nil).Once()
	repo.EXPECT().UpdateUpstream(ctx, mock.AnythingOfType("*upstream.Upstream")).Return(nil)
	repo.EXPECT().GetUpstream(ctx, upstreamID).Return(updated, nil).Once()
	cache.EXPECT().SaveUpstream(ctx, gatewayID.String(), mock.Anything).Return(nil)
	publisher.EXPECT().Publish(ctx, mock.Anything).Return(nil)
	descEmb.EXPECT().Process(ctx, mock.Anything).Return(nil)

	result, err := u.Update(ctx, gatewayID, upstreamID, validUpstreamRequest())

	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestUpdater_Update_UpstreamNotFound(t *testing.T) {
	u, repo, _, _, _, _ := setupUpdater(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	upstreamID := uuid.New()

	repo.EXPECT().GetUpstream(ctx, upstreamID).Return(nil, errors.New("not found"))

	result, err := u.Update(ctx, gatewayID, upstreamID, validUpstreamRequest())

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrUpstreamNotFound)
}

func TestUpdater_Update_GatewayMismatch(t *testing.T) {
	u, repo, _, _, _, _ := setupUpdater(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	upstreamID := uuid.New()

	existing := &upstream.Upstream{
		ID:        upstreamID,
		GatewayID: uuid.New(),
	}

	repo.EXPECT().GetUpstream(ctx, upstreamID).Return(existing, nil)

	result, err := u.Update(ctx, gatewayID, upstreamID, validUpstreamRequest())

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrUpstreamNotFound)
}

func TestUpdater_Update_InvalidEmbeddingProvider(t *testing.T) {
	u, _, _, _, _, _ := setupUpdater(t)
	ctx := context.Background()

	req := validUpstreamRequest()
	req.Embedding = &request.EmbeddingRequest{Provider: "invalid", Model: "model"}

	result, err := u.Update(ctx, uuid.New(), uuid.New(), req)

	assert.Nil(t, result)
	assert.ErrorIs(t, err, domain.ErrInvalidEmbeddingProvider)
}

func TestUpdater_Update_RepositoryError(t *testing.T) {
	u, repo, _, _, _, _ := setupUpdater(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	upstreamID := uuid.New()

	existing := &upstream.Upstream{
		ID:        upstreamID,
		GatewayID: gatewayID,
	}

	repo.EXPECT().GetUpstream(ctx, upstreamID).Return(existing, nil)
	repo.EXPECT().UpdateUpstream(ctx, mock.Anything).Return(errors.New("db error"))

	result, err := u.Update(ctx, gatewayID, upstreamID, validUpstreamRequest())

	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to update upstream")
}
