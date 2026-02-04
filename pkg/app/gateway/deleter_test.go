package gateway

import (
	"context"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	gatewayMocks "github.com/NeuralTrust/TrustGate/pkg/domain/gateway/mocks"
	apikeyMocks "github.com/NeuralTrust/TrustGate/pkg/domain/iam/apikey/mocks"
	cacheMocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	tlsMocks "github.com/NeuralTrust/TrustGate/pkg/infra/tls/mocks"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupDeleter(
	t *testing.T,
	repo *gatewayMocks.Repository,
	apiKeyRepo *apikeyMocks.Repository,
	publisher *cacheMocks.EventPublisher,
	tlsCertWriter *tlsMocks.CertWriter,
) Deleter {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	if tlsCertWriter == nil {
		tlsCertWriter = tlsMocks.NewCertWriter(t)
	}
	if apiKeyRepo == nil {
		apiKeyRepo = apikeyMocks.NewRepository(t)
		apiKeyRepo.EXPECT().ListWithSubject(mock.Anything, mock.Anything).Return(nil, nil).Maybe()
	}
	return NewDeleter(logger, repo, apiKeyRepo, publisher, tlsCertWriter)
}

func TestDeleter_Delete_Success(t *testing.T) {
	repo := gatewayMocks.NewRepository(t)
	apiKeyRepo := apikeyMocks.NewRepository(t)
	publisher := cacheMocks.NewEventPublisher(t)
	tlsCertWriter := tlsMocks.NewCertWriter(t)

	deleter := setupDeleter(t, repo, apiKeyRepo, publisher, tlsCertWriter)

	ctx := context.Background()
	gatewayID := uuid.New()

	apiKeyRepo.EXPECT().ListWithSubject(ctx, gatewayID).Return(nil, nil)
	repo.EXPECT().Delete(gatewayID).Return(nil)
	tlsCertWriter.EXPECT().DeleteAllGatewayCerts(ctx, gatewayID).Return(nil)
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

	deleter := setupDeleter(t, repo, nil, publisher, nil)

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

	deleter := setupDeleter(t, repo, nil, publisher, nil)

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
	apiKeyRepo := apikeyMocks.NewRepository(t)
	publisher := cacheMocks.NewEventPublisher(t)
	tlsCertWriter := tlsMocks.NewCertWriter(t)

	deleter := setupDeleter(t, repo, apiKeyRepo, publisher, tlsCertWriter)

	ctx := context.Background()
	gatewayID := uuid.New()

	apiKeyRepo.EXPECT().ListWithSubject(ctx, gatewayID).Return(nil, nil)
	repo.EXPECT().Delete(gatewayID).Return(nil)
	tlsCertWriter.EXPECT().DeleteAllGatewayCerts(ctx, gatewayID).Return(nil)
	publisher.EXPECT().Publish(
		ctx,
		mock.Anything,
	).Return(errors.New("redis connection failed"))

	// Even if publish fails, delete should succeed
	err := deleter.Delete(ctx, gatewayID)

	assert.NoError(t, err)
}
