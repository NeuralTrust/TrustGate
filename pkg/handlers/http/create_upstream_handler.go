package http

import (
	"fmt"
	"time"

	appUpstream "github.com/NeuralTrust/TrustGate/pkg/app/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auditlogs"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/factory"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type CreateUpstreamHandlerDeps struct {
	Logger                      *logrus.Logger
	Repo                        upstream.Repository
	GatewayRepo                 gateway.Repository
	Cache                       cache.Client
	DescriptionEmbeddingCreator appUpstream.DescriptionEmbeddingCreator
	Cfg                         *config.Config
	AuditService                auditlogs.Service
}

type createUpstreamHandler struct {
	logger                      *logrus.Logger
	cache                       cache.Client
	descriptionEmbeddingCreator appUpstream.DescriptionEmbeddingCreator
	repo                        upstream.Repository
	gatewayRepo                 gateway.Repository
	cfg                         *config.Config
	auditService                auditlogs.Service
}

func NewCreateUpstreamHandler(deps CreateUpstreamHandlerDeps) Handler {
	return &createUpstreamHandler{
		logger:                      deps.Logger,
		repo:                        deps.Repo,
		gatewayRepo:                 deps.GatewayRepo,
		cache:                       deps.Cache,
		descriptionEmbeddingCreator: deps.DescriptionEmbeddingCreator,
		cfg:                         deps.Cfg,
		auditService:                deps.AuditService,
	}
}

// Handle @Summary Create a new Upstream
// @Description Adds a new upstream under a gateway
// @Tags Upstreams
// @Accept json
// @Produce json
// @Param Authorization header string true "Authorization token"
// @Param gateway_id path string true "Gateway ID"
// @Param upstream body request.UpstreamRequest true "Upstream data"
// @Success 201 {object} upstream.Upstream "Upstream created successfully"
// @Router /api/v1/gateways/{gateway_id}/upstreams [post]
func (s *createUpstreamHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")

	var req request.UpstreamRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	if err := req.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Extra guard for per-target OAuth validation (defensive, mirrors DTO validation)
	for i, t := range req.Targets {
		if t.Auth != nil {
			if t.Auth.Type != request.AuthTypeOAuth2 || t.Auth.OAuth == nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("target %d: auth.type must be 'oauth2' and oauth config required", i)})
			}
			gt := t.Auth.OAuth.GrantType
			switch gt {
			case "client_credentials":
				if !t.Auth.OAuth.UseBasicAuth && t.Auth.OAuth.ClientID == "" {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("target %d: auth.oauth.client_id is required for client_credentials when use_basic_auth is false", i)})
				}
			case "authorization_code":
				if t.Auth.OAuth.Code == "" || t.Auth.OAuth.RedirectURI == "" {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("target %d: authorization_code requires code and redirect_uri", i)})
				}
			case "password":
				if t.Auth.OAuth.Username == "" || t.Auth.OAuth.Password == "" {
					return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("target %d: password grant requires username and password", i)})
				}
			}
		}
	}

	if req.Embedding != nil && req.Embedding.Provider != "" {
		if req.Embedding.Provider != factory.OpenAIProvider {
			return c.Status(fiber.StatusBadRequest).
				JSON(fiber.Map{"error": fmt.Sprintf("embedding provider '%s' is not allowed", req.Embedding.Provider)})
		}
	}

	// Validate gateway UUID format first
	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway uuid"})
	}

	// Validate that gateway exists
	_, err = s.gatewayRepo.Get(c.Context(), gatewayUUID)
	if err != nil {
		s.logger.WithError(err).WithField("gateway_id", gatewayID).Error("Gateway not found")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Gateway not found"})
	}

	entity, err := s.createUpstreamEntity(req, gatewayID)
	if err != nil {
		if err.Error() == "invalid gateway uuid" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if err := s.repo.CreateUpstream(c.Context(), entity); err != nil {
		s.logger.WithError(err).Error("failed to create upstream")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if err := s.cache.SaveUpstream(c.Context(), gatewayID, entity); err != nil {
		s.logger.WithError(err).Error("failed to cache upstream")
	}

	if err := s.descriptionEmbeddingCreator.Process(c.Context(), entity); err != nil {
		s.logger.WithError(err).Error("failed to process embeddings for upstream targets")
	}

	s.emitAuditLog(c, entity.ID.String(), entity.Name, auditlogs.StatusSuccess, "")

	return c.Status(fiber.StatusCreated).JSON(entity)
}

func (s *createUpstreamHandler) emitAuditLog(c *fiber.Ctx, targetID, targetName, status, errMsg string) {
	if s.auditService == nil {
		return
	}
	s.auditService.Emit(c, auditlogs.Event{
		Event: auditlogs.EventInfo{
			Type:         auditlogs.EventTypeUpstreamCreated,
			Category:     auditlogs.CategoryRunTimeSecurity,
			Status:       status,
			ErrorMessage: errMsg,
		},
		Target: auditlogs.Target{
			Type: auditlogs.TargetTypeUpstream,
			ID:   targetID,
			Name: targetName,
		},
		Context: auditlogs.Context{
			IPAddress: c.IP(),
			UserAgent: c.Get("User-Agent"),
			RequestID: c.Get("X-Request-ID"),
		},
	})
}

func (s *createUpstreamHandler) createUpstreamEntity(
	req request.UpstreamRequest,
	gatewayID string,
) (*upstream.Upstream, error) {
	now := time.Now()
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
			Credentials:     target.Credentials,
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

	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return nil, fmt.Errorf("invalid gateway uuid")
	}

	id, err := uuid.NewV6()
	if err != nil {
		s.logger.WithError(err).Error("failed to generate UUID")
		return nil, fmt.Errorf("failed to generate UUID")
	}

	var embedding *upstream.EmbeddingConfig
	if req.Embedding != nil {
		embedding = &upstream.EmbeddingConfig{
			Provider:    req.Embedding.Provider,
			Model:       req.Embedding.Model,
			Credentials: req.Embedding.Credentials,
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

	entity := upstream.Upstream{
		ID:              id,
		GatewayID:       gatewayUUID,
		Name:            req.Name,
		Algorithm:       req.Algorithm,
		Targets:         targets,
		EmbeddingConfig: embedding,
		HealthChecks:    healthCheck,
		Websocket:       websocket,
		Proxy:           proxy,
		Tags:            req.Tags,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	return &entity, nil
}
