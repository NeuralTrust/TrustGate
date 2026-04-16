package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	domainService "github.com/NeuralTrust/TrustGate/pkg/domain/service"
	serviceMocks "github.com/NeuralTrust/TrustGate/pkg/domain/service/mocks"
	cacheMocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func setupUpdater(t *testing.T) (Updater, *serviceMocks.Repository, *cacheMocks.EventPublisher) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	repo := serviceMocks.NewRepository(t)
	publisher := cacheMocks.NewEventPublisher(t)
	u := NewUpdater(logger, repo, publisher)
	return u, repo, publisher
}

func TestUpdater_Update_Success(t *testing.T) {
	u, repo, publisher := setupUpdater(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	serviceID := uuid.New()
	createdAt := time.Now().Add(-24 * time.Hour)

	existing := &domainService.Service{
		ID:        serviceID,
		GatewayID: gatewayID,
		Name:      "old-name",
		CreatedAt: createdAt,
	}

	repo.EXPECT().Get(ctx, serviceID.String()).Return(existing, nil)
	repo.EXPECT().Update(ctx, mock.AnythingOfType("*service.Service")).Return(nil)
	publisher.EXPECT().Publish(ctx, mock.Anything).Return(nil)

	result, err := u.Update(ctx, gatewayID, serviceID, validServiceRequest())

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test-service", result.Name)
	assert.Equal(t, createdAt, result.CreatedAt)
}

func TestUpdater_Update_ServiceNotFound(t *testing.T) {
	u, repo, _ := setupUpdater(t)
	ctx := context.Background()
	serviceID := uuid.New()

	repo.EXPECT().Get(ctx, serviceID.String()).Return(nil, errors.New("not found"))

	result, err := u.Update(ctx, uuid.New(), serviceID, validServiceRequest())

	assert.Nil(t, result)
	assert.True(t, domain.IsNotFoundError(err))
}

func TestUpdater_Update_InvalidUpstreamID(t *testing.T) {
	u, _, _ := setupUpdater(t)
	ctx := context.Background()

	req := validServiceRequest()
	req.UpstreamID = "not-a-uuid"

	result, err := u.Update(ctx, uuid.New(), uuid.New(), req)

	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid upstream ID")
}

func TestUpdater_Update_RepositoryError(t *testing.T) {
	u, repo, _ := setupUpdater(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	serviceID := uuid.New()

	existing := &domainService.Service{ID: serviceID, GatewayID: gatewayID}
	repo.EXPECT().Get(ctx, serviceID.String()).Return(existing, nil)
	repo.EXPECT().Update(ctx, mock.Anything).Return(errors.New("db error"))

	result, err := u.Update(ctx, gatewayID, serviceID, validServiceRequest())

	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to update service")
}

func TestUpdater_Update_PublishFails_StillReturns(t *testing.T) {
	u, repo, publisher := setupUpdater(t)
	ctx := context.Background()
	gatewayID := uuid.New()
	serviceID := uuid.New()

	existing := &domainService.Service{ID: serviceID, GatewayID: gatewayID}
	repo.EXPECT().Get(ctx, serviceID.String()).Return(existing, nil)
	repo.EXPECT().Update(ctx, mock.Anything).Return(nil)
	publisher.EXPECT().Publish(ctx, mock.Anything).Return(errors.New("publish error"))

	result, err := u.Update(ctx, gatewayID, serviceID, validServiceRequest())

	require.NoError(t, err)
	assert.NotNil(t, result)
}
