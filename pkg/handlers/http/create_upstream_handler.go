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
	gatewayUUID, err := uuid.Parse(c.Params("gateway_id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway uuid"})
	}

	var req request.UpstreamRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	if err := req.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	if req.Embedding != nil && req.Embedding.Provider != "" {
		if req.Embedding.Provider != factory.OpenAIProvider {
			return c.Status(fiber.StatusBadRequest).
				JSON(fiber.Map{"error": fmt.Sprintf("embedding provider '%s' is not allowed", req.Embedding.Provider)})
		}
	}

	if _, err := s.gatewayRepo.Get(c.UserContext(), gatewayUUID); err != nil {
		s.logger.WithError(err).WithField("gateway_id", gatewayUUID).Error("Gateway not found")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Gateway not found"})
	}

	entity, err := s.buildUpstreamEntity(req, gatewayUUID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if err := s.repo.CreateUpstream(c.UserContext(), entity); err != nil {
		s.logger.WithError(err).Error("failed to create upstream")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if err := s.cache.SaveUpstream(c.UserContext(), gatewayUUID.String(), entity); err != nil {
		s.logger.WithError(err).Error("failed to cache upstream")
	}

	if err := s.descriptionEmbeddingCreator.Process(c.UserContext(), entity); err != nil {
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

func (s *createUpstreamHandler) buildUpstreamEntity(
	req request.UpstreamRequest,
	gatewayID uuid.UUID,
) (*upstream.Upstream, error) {
	id, err := uuid.NewV6()
	if err != nil {
		s.logger.WithError(err).Error("failed to generate UUID")
		return nil, fmt.Errorf("failed to generate UUID")
	}

	now := time.Now()

	entity := upstream.Upstream{
		ID:              id,
		GatewayID:       gatewayID,
		Name:            req.Name,
		Algorithm:       req.Algorithm,
		Targets:         s.buildTargets(req.Targets),
		EmbeddingConfig: s.buildEmbeddingConfig(req.Embedding),
		HealthChecks:    s.buildHealthCheck(req.HealthChecks),
		Websocket:       s.buildWebsocketConfig(req.WebhookConfig),
		Proxy:           s.buildProxy(req.ProxyConfig),
		Tags:            req.Tags,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	return &entity, nil
}

func (s *createUpstreamHandler) buildTargets(targets []request.TargetRequest) []upstream.Target {
	result := make([]upstream.Target, 0, len(targets))
	for _, t := range targets {
		target := upstream.Target{
			ID:              t.ID,
			Weight:          t.Weight,
			Tags:            t.Tags,
			Headers:         t.Headers,
			Path:            t.Path,
			Host:            t.Host,
			Port:            t.Port,
			Protocol:        t.Protocol,
			Provider:        t.Provider,
			ProviderOptions: t.ProviderOptions,
			Models:          t.Models,
			DefaultModel:    t.DefaultModel,
			Description:     t.Description,
			Stream:          t.Stream,
			InsecureSSL:     t.InsecureSSL,
			Credentials:     t.Credentials,
		}
		if t.Auth != nil && t.Auth.Type == request.AuthTypeOAuth2 && t.Auth.OAuth != nil {
			target.Auth = &upstream.TargetAuth{
				Type:  upstream.AuthTypeOAuth2,
				OAuth: s.buildOAuthConfig(t.Auth.OAuth),
			}
		}
		result = append(result, target)
	}
	return result
}

func (s *createUpstreamHandler) buildOAuthConfig(o *request.UpstreamOAuthRequest) *upstream.TargetOAuthConfig {
	return &upstream.TargetOAuthConfig{
		TokenURL:     o.TokenURL,
		GrantType:    o.GrantType,
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		UseBasicAuth: o.UseBasicAuth,
		Scopes:       o.Scopes,
		Audience:     o.Audience,
		Code:         o.Code,
		RedirectURI:  o.RedirectURI,
		CodeVerifier: o.CodeVerifier,
		RefreshToken: o.RefreshToken,
		Username:     o.Username,
		Password:     o.Password,
		Extra:        o.Extra,
	}
}

func (s *createUpstreamHandler) buildEmbeddingConfig(e *request.EmbeddingRequest) *upstream.EmbeddingConfig {
	if e == nil {
		return nil
	}
	return &upstream.EmbeddingConfig{
		Provider:    e.Provider,
		Model:       e.Model,
		Credentials: e.Credentials,
	}
}

func (s *createUpstreamHandler) buildHealthCheck(h *request.HealthCheckRequest) *upstream.HealthCheck {
	if h == nil {
		return nil
	}
	return &upstream.HealthCheck{
		Passive:   h.Passive,
		Path:      h.Path,
		Headers:   h.Headers,
		Threshold: h.Threshold,
		Interval:  h.Interval,
	}
}

func (s *createUpstreamHandler) buildWebsocketConfig(w *request.WebhookConfigRequest) *upstream.WebsocketConfig {
	if w == nil {
		return nil
	}
	return &upstream.WebsocketConfig{
		EnableDirectCommunication: w.EnableDirectCommunication,
		ReturnErrorDetails:        w.ReturnErrorDetails,
		PingPeriod:                w.PingPeriod,
		PongWait:                  w.PongWait,
		HandshakeTimeout:          w.HandshakeTimeout,
		ReadBufferSize:            w.ReadBufferSize,
		WriteBufferSize:           w.WriteBufferSize,
	}
}

func (s *createUpstreamHandler) buildProxy(p *request.ProxyConfigRequest) *upstream.Proxy {
	if p == nil {
		return nil
	}
	protocol := p.Protocol
	if protocol == "" {
		protocol = "http"
	}
	return &upstream.Proxy{
		Host:     p.Host,
		Port:     p.Port,
		Protocol: protocol,
	}
}
