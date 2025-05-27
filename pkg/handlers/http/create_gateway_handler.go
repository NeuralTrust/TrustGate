package http

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	appTelemetry "github.com/NeuralTrust/TrustGate/pkg/app/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type createGatewayHandler struct {
	logger                      *logrus.Logger
	repo                        domainGateway.Repository
	updateGatewayCache          gateway.UpdateGatewayCache
	pluginChainValidator        plugin.ValidatePluginChain
	telemetryProvidersValidator appTelemetry.ExportersValidator
}

func NewCreateGatewayHandler(
	logger *logrus.Logger,
	repo domainGateway.Repository,
	updateGatewayCache gateway.UpdateGatewayCache,
	pluginChainValidator plugin.ValidatePluginChain,
	telemetryProvidersValidator appTelemetry.ExportersValidator,
) Handler {
	return &createGatewayHandler{
		logger:                      logger,
		repo:                        repo,
		updateGatewayCache:          updateGatewayCache,
		pluginChainValidator:        pluginChainValidator,
		telemetryProvidersValidator: telemetryProvidersValidator,
	}
}

// Handle @Summary      Create a new Gateway
// @Description  Creates a new gateway in the system
// @Tags         Gateways
// @Accept       json
// @Produce      json
// @Param        Authorization header string true "Authorization token"
// @Param        gateway body request.CreateGatewayRequest true "Gateway data"
// @Success      201 {object} gateway.Gateway "Gateway created successfully"
// @Failure      400 {object} map[string]interface{} "Invalid request data"
// @Router       /api/v1/gateways [post]
func (h *createGatewayHandler) Handle(c *fiber.Ctx) error {

	var req request.CreateGatewayRequest
	if err := c.BodyParser(&req); err != nil {
		h.logger.WithError(err).Error("Failed to bind request")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": ErrInvalidJsonPayload})
	}
	now := time.Now()
	req.CreatedAt = now
	req.UpdatedAt = now

	if err := req.Validate(); err != nil {
		h.logger.WithError(err).Error("invalid request data")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	id, err := uuid.NewV6()
	if err != nil {
		h.logger.WithError(err).Error("failed to generate UUID")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to generate UUID"})
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

	var telemetryObj *telemetry.Telemetry
	if req.Telemetry != nil {
		var exporters []types.Exporter
		for _, config := range req.Telemetry.Exporters {
			exporters = append(exporters, types.Exporter(config))
		}
		err = h.telemetryProvidersValidator.Validate(exporters)
		if err != nil {
			h.logger.WithError(err).Error("failed to validate telemetry providers")
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		telemetryObj = &telemetry.Telemetry{
			Exporters:           h.telemetryExportersToDomain(exporters),
			ExtraParams:         req.Telemetry.ExtraParams,
			EnablePluginTraces:  req.Telemetry.EnablePluginTraces,
			EnableRequestTraces: req.Telemetry.EnableRequestTraces,
			HeaderMapping:       req.Telemetry.HeaderMapping,
		}
	}

	var sessionConfig *domainGateway.SessionConfig
	if req.SessionConfig != nil {
		sessionConfig = &domainGateway.SessionConfig{
			Enabled:       req.SessionConfig.Enabled,
			HeaderName:    req.SessionConfig.HeaderName,
			BodyParamName: req.SessionConfig.BodyParamName,
			Mapping:       req.SessionConfig.Mapping,
			TTL:           req.SessionConfig.TTL,
		}
	}

	entity := domainGateway.Gateway{
		ID:              id,
		Name:            req.Name,
		Subdomain:       req.Subdomain,
		Status:          req.Status,
		RequiredPlugins: req.RequiredPlugins,
		Telemetry:       telemetryObj,
		ClientTLSConfig: h.mapClientTLSConfig(req.TlS),
		SecurityConfig:  securityConfig,
		SessionConfig:   sessionConfig,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.UpdatedAt,
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

func (h *createGatewayHandler) mapClientTLSConfig(
	req map[string]request.ClientTLSConfigRequest,
) map[string]types.ClientTLSConfig {
	if len(req) == 0 {
		return nil
	}

	result := make(map[string]types.ClientTLSConfig, len(req))
	for k, v := range req {
		result[k] = types.ClientTLSConfig{
			AllowInsecureConnections: v.AllowInsecureConnections,
			CACerts:                  v.CACert,
			ClientCerts: types.ClientTLSCert{
				Certificate: v.ClientCerts.Certificate,
				PrivateKey:  v.ClientCerts.PrivateKey,
			},
			CipherSuites:        v.CipherSuites,
			CurvePreferences:    v.CurvePreferences,
			DisableSystemCAPool: v.DisableSystemCAPool,
			MinVersion:          v.MinVersion,
			MaxVersion:          v.MaxVersion,
		}
	}
	return result
}
