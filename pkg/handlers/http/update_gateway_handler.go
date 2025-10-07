package http

import (
	"fmt"
	"time"

	appTelemetry "github.com/NeuralTrust/TrustGate/pkg/app/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	infraCache "github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/channel"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type updateGatewayHandler struct {
	logger                      *logrus.Logger
	repo                        domainGateway.Repository
	pluginManager               plugins.Manager
	publisher                   infraCache.EventPublisher
	telemetryProvidersValidator appTelemetry.ExportersValidator
}

func NewUpdateGatewayHandler(
	logger *logrus.Logger,
	repo domainGateway.Repository,
	pluginManager plugins.Manager,
	publisher infraCache.EventPublisher,
	telemetryProvidersValidator appTelemetry.ExportersValidator,
) Handler {
	return &updateGatewayHandler{
		logger:                      logger,
		repo:                        repo,
		pluginManager:               pluginManager,
		publisher:                   publisher,
		telemetryProvidersValidator: telemetryProvidersValidator,
	}
}

// Handle @Summary Update a Gateway
// @Description Updates an existing gateway
// @Tags Gateways
// @Param Authorization header string true "Authorization token"
// @Accept json
// @Produce json
// @Param gateway_id path string true "Gateway ID"
// @Param gateway body request.UpdateGatewayRequest true "Updated gateway data"
// @Success 204 "Gateway updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request data"
// @Router /api/v1/gateways/{gateway_id} [put]
func (h *updateGatewayHandler) Handle(c *fiber.Ctx) error {
	gatewayID := c.Params("gateway_id")
	gatewayUUID, err := uuid.Parse(gatewayID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid gateway ID"})
	}

	dbGateway, err := h.repo.Get(c.Context(), gatewayUUID)
	if err != nil {
		h.logger.WithError(err).Error("failed to get gateway")
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "gateway not found"})
	}

	var req request.UpdateGatewayRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.WithError(err).Error("failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	if req.Name != nil {
		dbGateway.Name = *req.Name
	}
	if req.Status != nil {
		dbGateway.Status = *req.Status
	}

	if req.RequiredPlugins != nil {
		// Initialize plugins map
		if dbGateway.RequiredPlugins == nil {
			dbGateway.RequiredPlugins = []types.PluginConfig{}
		}

		// Convert and validate plugins
		for _, cfg := range req.RequiredPlugins {
			if err := h.pluginManager.ValidatePlugin(cfg.Name, cfg); err != nil {
				h.logger.WithError(err).WithField("plugin", cfg.Name).Error("Invalid plugin configuration")
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("invalid plugin configuration: %v", err)})
			}
		}
		dbGateway.RequiredPlugins = req.RequiredPlugins
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
		dbGateway.SecurityConfig = securityConfig
	}

	dbGateway.UpdatedAt = time.Now()

	if req.Telemetry != nil {
		var exporters []types.Exporter
		for _, config := range req.Telemetry.Exporters {
			exporters = append(exporters, types.Exporter(config))
		}

		// Disallow duplicate exporters with the same provider name
		seenProviders := make(map[string]struct{}, len(exporters))
		for _, e := range exporters {
			if _, exists := seenProviders[e.Name]; exists {
				h.logger.WithField("provider", e.Name).Error("duplicate telemetry exporter provider")
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "duplicate telemetry exporter provider: " + e.Name})
			}
			seenProviders[e.Name] = struct{}{}
		}
		err = h.telemetryProvidersValidator.Validate(exporters)
		if err != nil {
			h.logger.WithError(err).Error("failed to validate telemetry providers")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		dbGateway.Telemetry = &telemetry.Telemetry{
			Exporters:           h.telemetryExporterToDomain(exporters),
			ExtraParams:         req.Telemetry.ExtraParams,
			EnablePluginTraces:  req.Telemetry.EnablePluginTraces,
			EnableRequestTraces: req.Telemetry.EnableRequestTraces,
		}
	}

	if req.SessionConfig != nil {
		if dbGateway.SessionConfig == nil {
			dbGateway.SessionConfig = &domainGateway.SessionConfig{}
		}
		dbGateway.SessionConfig.Enabled = req.SessionConfig.Enabled
		dbGateway.SessionConfig.HeaderName = req.SessionConfig.HeaderName
		dbGateway.SessionConfig.BodyParamName = req.SessionConfig.BodyParamName
		dbGateway.SessionConfig.Mapping = req.SessionConfig.Mapping
		dbGateway.SessionConfig.TTL = req.SessionConfig.TTL
	}

	if err := h.repo.Update(c.Context(), dbGateway); err != nil {
		h.logger.WithError(err).Error("Failed to update gateway")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to update gateway"})
	}

	err = h.publisher.Publish(c.Context(), channel.GatewayEventsChannel, event.UpdateGatewayCacheEvent{
		GatewayID: dbGateway.ID.String(),
	})
	if err != nil {
		h.logger.WithError(err).Error("failed to publish update gateway cache event")
	}

	return c.Status(fiber.StatusNoContent).JSON(fiber.Map{})
}

func (h *updateGatewayHandler) telemetryExporterToDomain(configs []types.Exporter) []telemetry.ExporterConfig {
	result := make([]telemetry.ExporterConfig, 0, len(configs))
	for _, cfg := range configs {
		result = append(result, telemetry.ExporterConfig{
			Name:     cfg.Name,
			Settings: cfg.Settings,
		})
	}
	return result
}
