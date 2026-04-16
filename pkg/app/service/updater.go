package service

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=service_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, gatewayID, serviceID uuid.UUID, req *request.ServiceRequest) (*service.Service, error)
}

type updater struct {
	logger    *logrus.Logger
	repo      service.Repository
	publisher infraCache.EventPublisher
}

func NewUpdater(
	logger *logrus.Logger,
	repo service.Repository,
	publisher infraCache.EventPublisher,
) Updater {
	return &updater{
		logger:    logger,
		repo:      repo,
		publisher: publisher,
	}
}

func (u *updater) Update(ctx context.Context, gatewayID, serviceID uuid.UUID, req *request.ServiceRequest) (*service.Service, error) {
	upstreamID, err := uuid.Parse(req.UpstreamID)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream ID: %w", err)
	}

	existingService, err := u.repo.Get(ctx, serviceID.String())
	if err != nil {
		u.logger.WithError(err).Error("failed to get existing service")
		return nil, domain.NewNotFoundError("service", serviceID)
	}

	entity := service.Service{
		ID:          serviceID,
		GatewayID:   gatewayID,
		Name:        req.Name,
		Type:        req.Type,
		Description: req.Description,
		Tags:        req.Tags,
		UpstreamID:  upstreamID,
		Host:        req.Host,
		Port:        req.Port,
		Protocol:    req.Protocol,
		Path:        req.Path,
		Headers:     req.Headers,
		Credentials: req.Credentials,
		CreatedAt:   existingService.CreatedAt,
	}

	if err := u.repo.Update(ctx, &entity); err != nil {
		u.logger.WithError(err).Error("failed to update service")
		return nil, fmt.Errorf("failed to update service: %w", err)
	}

	if err := u.publisher.Publish(ctx, event.DeleteServiceCacheEvent{
		ServiceID: entity.ID.String(),
		GatewayID: entity.GatewayID.String(),
	}); err != nil {
		u.logger.WithError(err).Error("failed to publish update service cache event")
	}

	return &entity, nil
}
