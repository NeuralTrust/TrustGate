package upstream

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/gcp"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=upstream_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, gatewayID, upstreamID uuid.UUID, req *request.UpstreamRequest) (*upstream.Upstream, error)
}

type updater struct {
	logger                      *logrus.Logger
	repo                        upstream.Repository
	publisher                   cache.EventPublisher
	cache                       cache.Client
	descriptionEmbeddingCreator DescriptionEmbeddingCreator
	saService                   gcp.ServiceAccountService
}

func NewUpdater(
	logger *logrus.Logger,
	repo upstream.Repository,
	publisher cache.EventPublisher,
	cache cache.Client,
	descriptionEmbeddingCreator DescriptionEmbeddingCreator,
	saService gcp.ServiceAccountService,
) Updater {
	return &updater{
		logger:                      logger,
		repo:                        repo,
		publisher:                   publisher,
		cache:                       cache,
		descriptionEmbeddingCreator: descriptionEmbeddingCreator,
		saService:                   saService,
	}
}

func (u *updater) Update(
	ctx context.Context,
	gatewayID, upstreamID uuid.UUID,
	req *request.UpstreamRequest,
) (*upstream.Upstream, error) {
	if req.Embedding != nil && req.Embedding.Provider != "" {
		if req.Embedding.Provider != factory.OpenAIProvider {
			return nil, fmt.Errorf("%w: '%s'", domain.ErrInvalidEmbeddingProvider, req.Embedding.Provider)
		}
	}

	targets, err := u.buildTargets(upstreamID.String(), req.Targets)
	if err != nil {
		return nil, err
	}

	existingUpstream, err := u.repo.GetUpstream(ctx, upstreamID)
	if err != nil {
		u.logger.WithError(err).Error("failed to get existing upstream")
		return nil, domain.ErrUpstreamNotFound
	}

	if existingUpstream.GatewayID != gatewayID {
		return nil, domain.ErrUpstreamNotFound
	}

	var embeddingConfig *upstream.EmbeddingConfig
	if req.Embedding != nil {
		embeddingConfig = upstream.NewEmbeddingConfig(req.Embedding.Provider, req.Embedding.Model, req.Embedding.Credentials)
	}

	var healthChecks *upstream.HealthCheck
	if req.HealthChecks != nil {
		healthChecks = upstream.NewHealthCheck(
			req.HealthChecks.Passive,
			req.HealthChecks.Path,
			req.HealthChecks.Headers,
			req.HealthChecks.Threshold,
			req.HealthChecks.Interval,
		)
	}

	var websocket *upstream.WebsocketConfig
	if req.WebhookConfig != nil {
		websocket = upstream.NewWebsocketConfig(
			req.WebhookConfig.EnableDirectCommunication,
			req.WebhookConfig.ReturnErrorDetails,
			req.WebhookConfig.PingPeriod,
			req.WebhookConfig.PongWait,
			req.WebhookConfig.HandshakeTimeout,
			req.WebhookConfig.ReadBufferSize,
			req.WebhookConfig.WriteBufferSize,
		)
	}

	var proxy *upstream.Proxy
	if req.ProxyConfig != nil {
		proxy = upstream.NewProxy(req.ProxyConfig.Host, req.ProxyConfig.Port, req.ProxyConfig.Protocol)
	}

	existingUpstream.Name = req.Name
	existingUpstream.Algorithm = req.Algorithm
	existingUpstream.Targets = targets
	existingUpstream.EmbeddingConfig = embeddingConfig
	existingUpstream.HealthChecks = healthChecks
	existingUpstream.Websocket = websocket
	existingUpstream.Proxy = proxy
	existingUpstream.Tags = req.Tags

	if err := u.repo.UpdateUpstream(ctx, existingUpstream); err != nil {
		u.logger.WithError(err).Error("failed to update upstream")
		return nil, fmt.Errorf("failed to update upstream: %w", err)
	}

	updatedUpstream, err := u.repo.GetUpstream(ctx, upstreamID)
	if err != nil {
		u.logger.WithError(err).Error("failed to get updated upstream")
		return nil, fmt.Errorf("failed to retrieve updated upstream: %w", err)
	}

	if err := u.cache.SaveUpstream(ctx, gatewayID.String(), updatedUpstream); err != nil {
		u.logger.WithError(err).Error("failed to update cache after upstream update")
	}

	if err := u.publisher.Publish(ctx, event.DeleteUpstreamCacheEvent{
		UpstreamID: upstreamID.String(),
		GatewayID:  gatewayID.String(),
	}); err != nil {
		u.logger.WithError(err).Error("failed to publish update upstream event")
	}

	if err := u.descriptionEmbeddingCreator.Process(ctx, updatedUpstream); err != nil {
		u.logger.WithError(err).Error("failed to process embeddings for upstream targets")
	}

	return updatedUpstream, nil
}

func (u *updater) buildTargets(upstreamID string, targets []request.TargetRequest) ([]upstream.Target, error) {
	result := make([]upstream.Target, 0, len(targets))
	for i, t := range targets {
		target := upstream.NewTarget(
			t.ID, t.Weight, t.Tags, t.Headers,
			t.Path, t.Host, t.Port, t.Protocol,
			t.Provider, t.ProviderOptions, t.Models,
			t.DefaultModel, t.Description,
			t.Stream, t.InsecureSSL, t.Credentials,
		)
		if t.Auth != nil {
			auth, err := buildTargetAuth(u.saService, i, t.Auth)
			if err != nil {
				return nil, err
			}
			if t.Auth.Type == request.AuthTypeGCPServiceAccount {
				u.saService.InvalidateSACache(upstreamID, t.ID)
			}
			target.Auth = auth
		}
		result = append(result, target)
	}
	return result, nil
}
