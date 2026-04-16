package service

import (
	"context"
	"errors"
	"testing"

	domainService "github.com/NeuralTrust/TrustGate/pkg/domain/service"
	serviceMocks "github.com/NeuralTrust/TrustGate/pkg/domain/service/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	cacheMocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupCreator(t *testing.T) (Creator, *serviceMocks.Repository, *cacheMocks.Client) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	repo := serviceMocks.NewRepository(t)
	cache := cacheMocks.NewClient(t)
	c := NewCreator(logger, repo, cache)
	return c, repo, cache
}

func validServiceRequest() *request.ServiceRequest {
	return &request.ServiceRequest{
		Name:       "test-service",
		Type:       "upstream",
		UpstreamID: uuid.New().String(),
	}
}

func TestCreator_Create_Success(t *testing.T) {
	c, repo, cache := setupCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()

	repo.EXPECT().Create(ctx, mock.AnythingOfType("*service.Service")).Return(nil)
	cache.EXPECT().SaveService(ctx, gatewayID.String(), mock.AnythingOfType("*service.Service")).Return(nil)

	result, err := c.Create(ctx, gatewayID, validServiceRequest())

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test-service", result.Name)
	assert.Equal(t, "upstream", result.Type)
	assert.Equal(t, gatewayID, result.GatewayID)
	assert.NotEqual(t, uuid.Nil, result.ID)
	assert.False(t, result.CreatedAt.IsZero())
}

func TestCreator_Create_InvalidUpstreamID(t *testing.T) {
	c, _, _ := setupCreator(t)
	ctx := context.Background()

	req := validServiceRequest()
	req.UpstreamID = "not-a-uuid"

	result, err := c.Create(ctx, uuid.New(), req)

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid upstream ID")
}

func TestCreator_Create_RepositoryError(t *testing.T) {
	c, repo, _ := setupCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()

	repo.EXPECT().Create(ctx, mock.Anything).Return(errors.New("db error"))

	result, err := c.Create(ctx, gatewayID, validServiceRequest())

	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to create service")
}

func TestCreator_Create_CacheFails_StillReturns(t *testing.T) {
	c, repo, cache := setupCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()

	repo.EXPECT().Create(ctx, mock.Anything).Return(nil)
	cache.EXPECT().SaveService(ctx, mock.Anything, mock.Anything).Return(errors.New("cache error"))

	result, err := c.Create(ctx, gatewayID, validServiceRequest())

	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestCreator_Create_UsesFactoryTimestamps(t *testing.T) {
	c, repo, cache := setupCreator(t)
	ctx := context.Background()
	gatewayID := uuid.New()

	var captured *domainService.Service
	repo.EXPECT().Create(ctx, mock.AnythingOfType("*service.Service")).
		Run(func(_ context.Context, svc *domainService.Service) {
			captured = svc
		}).Return(nil)
	cache.EXPECT().SaveService(ctx, mock.Anything, mock.Anything).Return(nil)

	_, err := c.Create(ctx, gatewayID, validServiceRequest())

	require.NoError(t, err)
	require.NotNil(t, captured)
	assert.False(t, captured.CreatedAt.IsZero())
	assert.Equal(t, captured.CreatedAt, captured.UpdatedAt)
}
