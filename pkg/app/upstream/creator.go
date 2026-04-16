package upstream

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/gcp"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=upstream_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, gatewayID uuid.UUID, req *request.UpstreamRequest) (*upstream.Upstream, error)
}

type creator struct {
	logger                      *logrus.Logger
	repo                        upstream.Repository
	gatewayRepo                 gateway.Repository
	cache                       cache.Client
	descriptionEmbeddingCreator DescriptionEmbeddingCreator
	saService                   gcp.ServiceAccountService
}

func NewCreator(
	logger *logrus.Logger,
	repo upstream.Repository,
	gatewayRepo gateway.Repository,
	cache cache.Client,
	descriptionEmbeddingCreator DescriptionEmbeddingCreator,
	saService gcp.ServiceAccountService,
) Creator {
	return &creator{
		logger:                      logger,
		repo:                        repo,
		gatewayRepo:                 gatewayRepo,
		cache:                       cache,
		descriptionEmbeddingCreator: descriptionEmbeddingCreator,
		saService:                   saService,
	}
}

func (c *creator) Create(ctx context.Context, gatewayID uuid.UUID, req *request.UpstreamRequest) (*upstream.Upstream, error) {
	if req.Embedding != nil && req.Embedding.Provider != "" {
		if req.Embedding.Provider != factory.OpenAIProvider {
			return nil, fmt.Errorf("%w: '%s'", domain.ErrInvalidEmbeddingProvider, req.Embedding.Provider)
		}
	}

	if _, err := c.gatewayRepo.Get(ctx, gatewayID); err != nil {
		c.logger.WithError(err).WithField("gateway_id", gatewayID).Error("gateway not found")
		return nil, domain.ErrGatewayNotFound
	}

	targets, err := c.buildTargets(req.Targets)
	if err != nil {
		return nil, err
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

	entity, err := upstream.New(upstream.CreateParams{
		GatewayID:       gatewayID,
		Name:            req.Name,
		Algorithm:       req.Algorithm,
		Targets:         targets,
		EmbeddingConfig: embeddingConfig,
		HealthChecks:    healthChecks,
		Websocket:       websocket,
		Proxy:           proxy,
		Tags:            req.Tags,
	})
	if err != nil {
		return nil, err
	}

	if err := c.repo.CreateUpstream(ctx, entity); err != nil {
		c.logger.WithError(err).Error("failed to create upstream")
		return nil, fmt.Errorf("failed to create upstream: %w", err)
	}

	if err := c.cache.SaveUpstream(ctx, gatewayID.String(), entity); err != nil {
		c.logger.WithError(err).Error("failed to cache upstream")
	}

	if err := c.descriptionEmbeddingCreator.Process(ctx, entity); err != nil {
		c.logger.WithError(err).Error("failed to process embeddings for upstream targets")
	}

	return entity, nil
}

func (c *creator) buildTargets(targets []request.TargetRequest) ([]upstream.Target, error) {
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
			auth, err := buildTargetAuth(c.saService, i, t.Auth)
			if err != nil {
				return nil, err
			}
			target.Auth = auth
		}
		result = append(result, target)
	}
	return result, nil
}
