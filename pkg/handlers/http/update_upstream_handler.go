package http

import (
	"fmt"

	appUpstream "github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/oauth"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type updateUpstreamHandler struct {
	logger                      *logrus.Logger
	repo                        upstream.Repository
	publisher                   infraCache.EventPublisher
	descriptionEmbeddingCreator appUpstream.DescriptionEmbeddingCreator
	cache                       *cache.Cache
	cfg                         *config.Config
}

func NewUpdateUpstreamHandler(
	logger *logrus.Logger,
	repo upstream.Repository,
	publisher infraCache.EventPublisher,
	cache *cache.Cache,
	descriptionEmbeddingCreator appUpstream.DescriptionEmbeddingCreator,
	cfg *config.Config,
) Handler {
	return &updateUpstreamHandler{
		logger:                      logger,
		repo:                        repo,
		publisher:                   publisher,
		descriptionEmbeddingCreator: descriptionEmbeddingCreator,
		cache:                       cache,
		cfg:                         cfg,
	}
}

// Handle @Summary Update an Upstream
// @Description Updates an existing upstream
// @Tags Upstreams
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param upstream_id path string true "Upstream ID"
// @Param upstream body request.UpstreamRequest true "Updated upstream data"
// @Success 200 {object} upstream.Upstream "Upstream updated successfully"
// @Router /api/v1/gateways/{gateway_id}/upstreams/{upstream_id} [put]
func (s *updateUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	upstreamID := c.Params("upstream_id")

	var req request.UpstreamRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	if err := req.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Defensive per-target auth validation mirroring DTO rules
	for i, t := range req.Targets {
		if t.Auth != nil {
			if t.Auth.Type != request.AuthTypeOAuth2 || t.Auth.OAuth == nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("target %d: auth.type must be 'oauth2' and oauth config required", i)})
			}
			switch t.Auth.OAuth.GrantType {
			case string(oauth.GrantTypeClientCredentials):
				if !t.Auth.OAuth.UseBasicAuth && t.Auth.OAuth.ClientID == "" {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("target %d: auth.oauth.client_id is required for client_credentials when use_basic_auth is false", i)})
				}
			case string(oauth.GrantTypeAuthorizationCode):
				if t.Auth.OAuth.Code == "" || t.Auth.OAuth.RedirectURI == "" {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("target %d: authorization_code requires code and redirect_uri", i)})
				}
			case string(oauth.GrantTypePassword):
				if t.Auth.OAuth.Username == "" || t.Auth.OAuth.Password == "" {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("target %d: password grant requires username and password", i)})
				}
			}
		}
	}

	if req.Embedding != nil && req.Embedding.Provider != "" {
		if req.Embedding.Provider != factory.OpenAIProvider {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("embedding provider '%s' is not allowed", req.Embedding.Provider)})
		}
	}

	id, err := uuid.Parse(upstreamID)
	if err != nil {
		s.logger.WithError(err).Error("failed to parse upstream ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid upstream ID"})
	}

	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("failed to parse gateway ID")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
	}

	var targets []upstream.Target
	for _, target := range req.Targets {
		t := upstream.Target{
			ID:              target.ID,
			Weight:          target.Weight,
			Tags:            target.Tags,
			Headers:         target.Headers,
			Path:            target.Path,
			Host:            target.Host,
			Port:            target.Port,
			Protocol:        target.Protocol,
			Provider:        target.Provider,
			ProviderOptions: target.ProviderOptions,
			Models:          target.Models,
			DefaultModel:    target.DefaultModel,
			Description:     target.Description,
			Stream:          target.Stream,
			InsecureSSL:     target.InsecureSSL,
			Credentials:     domain.CredentialsJSON(target.Credentials),
		}
		if target.Auth != nil && target.Auth.Type == request.AuthTypeOAuth2 && target.Auth.OAuth != nil {
			t.Auth = &upstream.TargetAuth{
				Type: upstream.AuthTypeOAuth2,
				OAuth: &upstream.TargetOAuthConfig{
					TokenURL:     target.Auth.OAuth.TokenURL,
					GrantType:    target.Auth.OAuth.GrantType,
					ClientID:     target.Auth.OAuth.ClientID,
					ClientSecret: target.Auth.OAuth.ClientSecret,
					UseBasicAuth: target.Auth.OAuth.UseBasicAuth,
					Scopes:       target.Auth.OAuth.Scopes,
					Audience:     target.Auth.OAuth.Audience,
					Code:         target.Auth.OAuth.Code,
					RedirectURI:  target.Auth.OAuth.RedirectURI,
					CodeVerifier: target.Auth.OAuth.CodeVerifier,
					RefreshToken: target.Auth.OAuth.RefreshToken,
					Username:     target.Auth.OAuth.Username,
					Password:     target.Auth.OAuth.Password,
					Extra:        target.Auth.OAuth.Extra,
				},
			}
		}
		targets = append(targets, t)
	}

	var healthCheck *upstream.HealthCheck
	if req.HealthChecks != nil {
		healthCheck = &upstream.HealthCheck{
			Passive:   req.HealthChecks.Passive,
			Path:      req.HealthChecks.Path,
			Headers:   req.HealthChecks.Headers,
			Threshold: req.HealthChecks.Threshold,
			Interval:  req.HealthChecks.Interval,
		}
	}

	var embedding *upstream.EmbeddingConfig
	if req.Embedding != nil {
		embedding = &upstream.EmbeddingConfig{
			Provider:    req.Embedding.Provider,
			Model:       req.Embedding.Model,
			Credentials: domain.CredentialsJSON(req.Embedding.Credentials),
		}
	}

	var proxy *upstream.Proxy
	if req.ProxyConfig != nil {
		proxy = &upstream.Proxy{
			Host:     req.ProxyConfig.Host,
			Port:     req.ProxyConfig.Port,
			Protocol: req.ProxyConfig.Protocol,
		}
	}

	var websocket *upstream.WebsocketConfig
	if req.WebhookConfig != nil {
		websocket = &upstream.WebsocketConfig{
			EnableDirectCommunication: req.WebhookConfig.EnableDirectCommunication,
			ReturnErrorDetails:        req.WebhookConfig.ReturnErrorDetails,
			PingPeriod:                req.WebhookConfig.PingPeriod,
			PongWait:                  req.WebhookConfig.PongWait,
			HandshakeTimeout:          req.WebhookConfig.HandshakeTimeout,
			ReadBufferSize:            req.WebhookConfig.ReadBufferSize,
			WriteBufferSize:           req.WebhookConfig.WriteBufferSize,
		}
	}

	// Fetch the existing upstream first to preserve metadata
	existingUpstream, err := s.repo.GetUpstream(c.Context(), id)
	if err != nil {
		s.logger.WithError(err).Error("failed to get existing upstream")
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "upstream not found"})
	}

	// Ownership check - ensure upstream belongs to the specified gateway
	if existingUpstream.GatewayID != gatewayUUID {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "upstream not found"})
	}

	// Update the fields with new values while preserving existing metadata
	existingUpstream.Name = req.Name
	existingUpstream.Algorithm = req.Algorithm
	existingUpstream.Targets = targets
	existingUpstream.EmbeddingConfig = embedding
	existingUpstream.HealthChecks = healthCheck
	existingUpstream.Websocket = websocket
	existingUpstream.Proxy = proxy
	existingUpstream.Tags = req.Tags

	if err := s.repo.UpdateUpstream(c.Context(), existingUpstream); err != nil {
		s.logger.WithError(err).Error("failed to update upstream")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// Re-fetch the upstream from database to ensure we return what's actually persisted
	updatedUpstream, err := s.repo.GetUpstream(c.Context(), id)
	if err != nil {
		s.logger.WithError(err).Error("failed to get updated upstream")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to retrieve updated upstream"})
	}

	// Immediately update the cache to ensure consistency with GET requests
	if err := s.cache.SaveUpstream(c.Context(), gatewayID, updatedUpstream); err != nil {
		s.logger.WithError(err).Error("failed to update cache after upstream update")
	}

	err = s.publisher.Publish(c.Context(), channel.GatewayEventsChannel, event.UpdateUpstreamCacheEvent{
		UpstreamID: upstreamID,
		GatewayID:  gatewayID,
	})
	if err != nil {
		s.logger.WithError(err).Error("failed to publish update upstream event")
	}
	if err := s.descriptionEmbeddingCreator.Process(c.Context(), updatedUpstream); err != nil {
		s.logger.WithError(err).Error("Failed to process embeddings for upstream targets")
	}

	return c.Status(fiber.StatusOK).JSON(updatedUpstream)
}

// upstream-level Auth removed; per-target auth is supported instead
