package gateway

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/iam/apikey"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	infraTLS "github.com/NeuralTrust/TrustGate/pkg/infra/tls"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

//go:generate mockery --name=Deleter --dir=. --output=./mocks --filename=gateway_deleter_mock.go --case=underscore --with-expecter
type Deleter interface {
	Delete(ctx context.Context, id uuid.UUID) error
}

type deleter struct {
	logger        *logrus.Logger
	repo          domainGateway.Repository
	apiKeyRepo    apikey.Repository
	publisher     infraCache.EventPublisher
	tlsCertWriter infraTLS.CertWriter
}

func NewDeleter(
	logger *logrus.Logger,
	repo domainGateway.Repository,
	apiKeyRepo apikey.Repository,
	publisher infraCache.EventPublisher,
	tlsCertWriter infraTLS.CertWriter,
) Deleter {
	return &deleter{
		logger:        logger,
		repo:          repo,
		apiKeyRepo:    apiKeyRepo,
		publisher:     publisher,
		tlsCertWriter: tlsCertWriter,
	}
}

func (d *deleter) Delete(ctx context.Context, id uuid.UUID) error {
	// Delete all API keys with subject = gateway_id
	if err := d.deleteAPIKeys(ctx, id); err != nil {
		d.logger.WithError(err).Warn("failed to delete API keys for gateway")
	}

	if err := d.repo.Delete(id); err != nil {
		if domain.IsNotFoundError(err) {
			return err
		}
		d.logger.WithError(err).Error("Failed to delete gateway")
		return err
	}

	// Delete all TLS certificates for this gateway
	if err := d.tlsCertWriter.DeleteAllGatewayCerts(ctx, id); err != nil {
		d.logger.WithError(err).Warn("failed to delete TLS certificates for gateway")
	}

	if err := d.publisher.Publish(
		ctx,
		event.DeleteGatewayCacheEvent{
			GatewayID: id.String(),
		},
	); err != nil {
		d.logger.WithError(err).Error("failed to publish gateway event")
	}

	return nil
}

func (d *deleter) deleteAPIKeys(ctx context.Context, gatewayID uuid.UUID) error {
	if d.apiKeyRepo == nil {
		return nil
	}

	keys, err := d.apiKeyRepo.ListWithSubject(ctx, gatewayID)
	if err != nil {
		d.logger.WithError(err).Error("failed to list API keys by gateway subject")
		return err
	}

	for _, k := range keys {
		if err := d.apiKeyRepo.DeleteWithSubject(ctx, k.ID, gatewayID); err != nil {
			d.logger.WithError(err).WithField("api_key_id", k.ID).Error("failed to delete API key")
			return err
		}
	}

	return nil
}
