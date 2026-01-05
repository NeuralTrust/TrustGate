package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	gatewayMocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	cacheMocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupDeleter(
	t *testing.T,
	repo *gatewayMocks.Repository,
	publisher *cacheMocks.EventPublisher,
) Deleter {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	return NewDeleter(logger, repo, publisher)
}

func TestDeleter_Delete_Success(t *testing.T) {
	repo := gatewayMocks.NewRepository(t)
	publisher := cacheMocks.NewEventPublisher(t)

	deleter := setupDeleter(t, repo, publisher)

	ctx := context.Background()
	gatewayID := uuid.New()

	repo.EXPECT().Delete(gatewayID).Return(nil)
	publisher.EXPECT().Publish(
		ctx,
		mock.MatchedBy(func(ev interface{}) bool {
			return true
		}),
	).Return(nil)

	err := deleter.Delete(ctx, gatewayID)

	assert.NoError(t, err)
}

func TestDeleter_Delete_NotFound(t *testing.T) {
	repo := gatewayMocks.NewRepository(t)
	publisher := cacheMocks.NewEventPublisher(t)

	deleter := setupDeleter(t, repo, publisher)

	ctx := context.Background()
	gatewayID := uuid.New()

	notFoundErr := domain.NewNotFoundError("gateway", gatewayID)
	repo.EXPECT().Delete(gatewayID).Return(notFoundErr)

	err := deleter.Delete(ctx, gatewayID)

	assert.Error(t, err)
	assert.True(t, domain.IsNotFoundError(err))
}

func TestDeleter_Delete_RepositoryError(t *testing.T) {
	repo := gatewayMocks.NewRepository(t)
	publisher := cacheMocks.NewEventPublisher(t)

	deleter := setupDeleter(t, repo, publisher)

	ctx := context.Background()
	gatewayID := uuid.New()

	dbError := errors.New("database connection failed")
	repo.EXPECT().Delete(gatewayID).Return(dbError)

	err := deleter.Delete(ctx, gatewayID)

	assert.Error(t, err)
	assert.Equal(t, dbError, err)
}

func TestDeleter_Delete_PublishEventFails_StillReturnsSuccess(t *testing.T) {
	repo := gatewayMocks.NewRepository(t)
	publisher := cacheMocks.NewEventPublisher(t)

	deleter := setupDeleter(t, repo, publisher)

	ctx := context.Background()
	gatewayID := uuid.New()

	repo.EXPECT().Delete(gatewayID).Return(nil)
	publisher.EXPECT().Publish(
		ctx,
		mock.Anything,
	).Return(errors.New("redis connection failed"))

	// Even if publish fails, delete should succeed
	err := deleter.Delete(ctx, gatewayID)

	assert.NoError(t, err)
}
