package service

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=service_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, gatewayID uuid.UUID, req *request.ServiceRequest) (*service.Service, error)
}

type creator struct {
	logger *logrus.Logger
	repo   service.Repository
	cache  cache.Client
}

func NewCreator(
	logger *logrus.Logger,
	repo service.Repository,
	cache cache.Client,
) Creator {
	return &creator{
		logger: logger,
		repo:   repo,
		cache:  cache,
	}
}

func (c *creator) Create(ctx context.Context, gatewayID uuid.UUID, req *request.ServiceRequest) (*service.Service, error) {
	upstreamID, err := uuid.Parse(req.UpstreamID)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream ID: %w", err)
	}

	entity, err := service.New(service.CreateParams{
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
	})
	if err != nil {
		return nil, err
	}

	if err := c.repo.Create(ctx, entity); err != nil {
		c.logger.WithError(err).Error("failed to create service")
		return nil, fmt.Errorf("failed to create service: %w", err)
	}

	if err := c.cache.SaveService(ctx, gatewayID.String(), entity); err != nil {
		c.logger.WithError(err).Error("failed to cache service")
	}

	return entity, nil
}
