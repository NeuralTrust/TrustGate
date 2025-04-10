package http

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	appTelemetry "github.com/NeuralTrust/TrustGate/pkg/app/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type createGatewayHandler struct {
	logger                    *logrus.Logger
	repo                      domainGateway.Repository
	updateGatewayCache        gateway.UpdateGatewayCache
	pluginChainValidator      plugin.ValidatePluginChain
	telemetryProvidersBuilder appTelemetry.ExportersBuilder
}

func NewCreateGatewayHandler(
	logger *logrus.Logger,
	repo domainGateway.Repository,
	updateGatewayCache gateway.UpdateGatewayCache,
	pluginChainValidator plugin.ValidatePluginChain,
	telemetryProvidersBuilder appTelemetry.ExportersBuilder,
) Handler {
	return &createGatewayHandler{
		logger:                    logger,
		repo:                      repo,
		updateGatewayCache:        updateGatewayCache,
		pluginChainValidator:      pluginChainValidator,
		telemetryProvidersBuilder: telemetryProvidersBuilder,
	}
}

// Handle @Summary      Create a new Gateway
// @Description  Creates a new gateway in the system
// @Tags         Gateways
// @Accept       json
// @Produce      json
// @Param        gateway body types.CreateGatewayRequest true "Gateway data"
// @Success      201 {object} gateway.Gateway "Gateway created successfully"
// @Failure      400 {object} map[string]interface{} "Invalid request data"
// @Router       /api/v1/gateways [post]
func (h *createGatewayHandler) Handle(c *fiber.Ctx) error {

	var req types.CreateGatewayRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.WithError(err).Error("Failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}

	now := time.Now()
	req.CreatedAt = now
	req.UpdatedAt = now

	id, err := uuid.NewV6()
	if err != nil {
		h.logger.WithError(err).Error("failed to generate UUID")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate UUID"})
	}

	var telemetryConfigs []types.Exporter

	for _, config := range req.Telemetry.Config {
		telemetryConfigs = append(telemetryConfigs, types.Exporter(config))
	}

	_, err = h.telemetryProvidersBuilder.Build(telemetryConfigs)
	if err != nil {
		h.logger.WithError(err).Error("failed to validate telemetry providers")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var securityConfig *domain.SecurityConfigJSON
	if req.SecurityConfig != nil {
		securityConfig = &domain.SecurityConfigJSON{
			AllowedHosts:            req.SecurityConfig.AllowedHosts,
			AllowedHostsAreRegex:    req.SecurityConfig.AllowedHostsAreRegex,
			SSLRedirect:             req.SecurityConfig.SSLRedirect,
			SSLHost:                 req.SecurityConfig.SSLHost,
			SSLProxyHeaders:         req.SecurityConfig.SSLProxyHeaders,
			STSSeconds:              req.SecurityConfig.STSSeconds,
			STSIncludeSubdomains:    req.SecurityConfig.STSIncludeSubdomains,
			FrameDeny:               req.SecurityConfig.FrameDeny,
			CustomFrameOptionsValue: req.SecurityConfig.CustomFrameOptionsValue,
			ReferrerPolicy:          req.SecurityConfig.ReferrerPolicy,
			ContentSecurityPolicy:   req.SecurityConfig.ContentSecurityPolicy,
			ContentTypeNosniff:      req.SecurityConfig.ContentTypeNosniff,
			BrowserXSSFilter:        req.SecurityConfig.BrowserXSSFilter,
			IsDevelopment:           req.SecurityConfig.IsDevelopment,
		}
	}

	entity := domainGateway.Gateway{
		ID:              id,
		Name:            req.Name,
		Subdomain:       req.Subdomain,
		Status:          req.Status,
		RequiredPlugins: req.RequiredPlugins,
		Telemetry: &telemetry.Telemetry{
			Exporters: h.telemetryExportersToDomain(telemetryConfigs),
		},
		SecurityConfig: securityConfig,
		CreatedAt:      req.CreatedAt,
		UpdatedAt:      req.UpdatedAt,
	}

	err = h.pluginChainValidator.Validate(c.Context(), id, entity.RequiredPlugins)
	if err != nil {
		h.logger.WithError(err).Error("failed to validate plugin chain")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	if err := h.repo.Save(c.Context(), &entity); err != nil {
		h.logger.WithError(err).Error("Failed to create gateway")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if err := h.updateGatewayCache.Update(c.Context(), &entity); err != nil {
		h.logger.WithError(err).Error("Failed to update gateway cache")
	}

	return c.Status(fiber.StatusCreated).JSON(entity)
}

func (h *createGatewayHandler) telemetryExportersToDomain(configs []types.Exporter) []telemetry.ExporterConfig {
	result := make([]telemetry.ExporterConfig, 0, len(configs))
	for _, cfg := range configs {
		result = append(result, telemetry.ExporterConfig{
			Name:     cfg.Name,
			Settings: cfg.Settings,
		})
	}
	return result
}
