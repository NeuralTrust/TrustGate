package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/plugin"
	appTelemetry "github.com/NeuralTrust/TrustGate/pkg/app/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/domain"
	domainGateway "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/request"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	infraTLS "github.com/NeuralTrust/TrustGate/pkg/infra/tls"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=gateway_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, req *request.CreateGatewayRequest, gatewayID string) (*domainGateway.Gateway, error)
}

type creator struct {
	logger                      *logrus.Logger
	repo                        domainGateway.Repository
	updateGatewayCache          UpdateGatewayCache
	pluginChainValidator        plugin.ValidatePluginChain
	telemetryProvidersValidator appTelemetry.ExportersValidator
	tlsCertWriter               infraTLS.CertWriter
}

func NewCreator(
	logger *logrus.Logger,
	repo domainGateway.Repository,
	updateGatewayCache UpdateGatewayCache,
	pluginChainValidator plugin.ValidatePluginChain,
	telemetryProvidersValidator appTelemetry.ExportersValidator,
	tlsCertWriter infraTLS.CertWriter,
) Creator {
	return &creator{
		logger:                      logger,
		repo:                        repo,
		updateGatewayCache:          updateGatewayCache,
		pluginChainValidator:        pluginChainValidator,
		telemetryProvidersValidator: telemetryProvidersValidator,
		tlsCertWriter:               tlsCertWriter,
	}
}

func (c *creator) Create(
	ctx context.Context,
	req *request.CreateGatewayRequest,
	gatewayID string,
) (*domainGateway.Gateway, error) {
	now := time.Now()
	req.CreatedAt = now
	req.UpdatedAt = now

	var id uuid.UUID
	var err error
	if gatewayID != "" {
		id, err = uuid.Parse(gatewayID)
		if err != nil {
			c.logger.WithError(err).Error("failed to parse gateway id")
			return nil, fmt.Errorf("failed to parse gateway id: %w", err)
		}
	} else {
		id, err = uuid.NewV6()
		if err != nil {
			c.logger.WithError(err).Error("failed to generate UUID")
			return nil, fmt.Errorf("failed to generate UUID: %w", err)
		}
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
		var exporters []types.ExporterDTO
		for _, config := range req.Telemetry.Exporters {
			exporters = append(exporters, types.ExporterDTO(config))
		}

		// Disallow duplicate exporters with the same provider name
		seenProviders := make(map[string]struct{}, len(exporters))
		for _, e := range exporters {
			if _, exists := seenProviders[e.Name]; exists {
				c.logger.WithField("provider", e.Name).Error("duplicate telemetry exporter provider")
				return nil, fmt.Errorf("%w: %s", pluginTypes.ErrDuplicateTelemetryExporter, e.Name)
			}
			seenProviders[e.Name] = struct{}{}
		}
		err = c.telemetryProvidersValidator.Validate(exporters)
		if err != nil {
			c.logger.WithError(err).Error("failed to validate telemetry providers")
			return nil, fmt.Errorf("%w: %w", pluginTypes.ErrTelemetryValidation, err)
		}
		telemetryObj = &telemetry.Telemetry{
			Exporters:           c.telemetryExportersToDomain(exporters),
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

	clientTLSConfig, err := c.mapClientTLSConfig(id, req.TlS)
	if err != nil {
		c.logger.WithError(err).Error("failed to write TLS certificates")
		return nil, fmt.Errorf("failed to write TLS certificates: %w", err)
	}

	entity := domainGateway.Gateway{
		ID:              id,
		Name:            req.Name,
		Status:          req.Status,
		RequiredPlugins: req.RequiredPlugins,
		Telemetry:       telemetryObj,
		ClientTLSConfig: clientTLSConfig,
		SecurityConfig:  securityConfig,
		SessionConfig:   sessionConfig,
		CreatedAt:       req.CreatedAt,
		UpdatedAt:       req.UpdatedAt,
	}

	err = c.pluginChainValidator.Validate(ctx, id, entity.RequiredPlugins)
	if err != nil {
		c.logger.WithError(err).Error("failed to validate plugin chain")
		return nil, fmt.Errorf("%w: %w", pluginTypes.ErrPluginChainValidation, err)
	}

	if err := c.repo.Save(ctx, &entity); err != nil {
		c.logger.WithError(err).Error("Failed to create gateway")
		return nil, fmt.Errorf("failed to create gateway: %w", err)
	}

	if err := c.updateGatewayCache.Update(ctx, &entity); err != nil {
		c.logger.WithError(err).Error("Failed to update gateway cache")
	}

	return &entity, nil
}

func (c *creator) telemetryExportersToDomain(configs []types.ExporterDTO) []telemetry.ExporterConfig {
	result := make([]telemetry.ExporterConfig, 0, len(configs))
	for _, cfg := range configs {
		result = append(result, telemetry.ExporterConfig{
			Name:     cfg.Name,
			Settings: cfg.Settings,
		})
	}
	return result
}

func (c *creator) mapClientTLSConfig(
	gatewayID uuid.UUID,
	req map[string]request.ClientTLSConfigRequest,
) (map[string]types.ClientTLSConfigDTO, error) {
	if len(req) == 0 {
		return nil, nil
	}

	result := make(map[string]types.ClientTLSConfigDTO, len(req))
	for host, v := range req {
		// Write certificate files and get their paths
		paths, err := c.tlsCertWriter.WriteCerts(
			gatewayID,
			host,
			v.CACert,
			v.ClientCerts.Certificate,
			v.ClientCerts.PrivateKey,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to write TLS certs for host %s: %w", host, err)
		}

		result[host] = types.ClientTLSConfigDTO{
			AllowInsecureConnections: v.AllowInsecureConnections,
			CACerts:                  paths.CACertPath,
			ClientCerts: types.ClientTLSCertDTO{
				Certificate: paths.ClientCertPath,
				PrivateKey:  paths.ClientKeyPath,
			},
			CipherSuites:        v.CipherSuites,
			CurvePreferences:    v.CurvePreferences,
			DisableSystemCAPool: v.DisableSystemCAPool,
			MinVersion:          v.MinVersion,
			MaxVersion:          v.MaxVersion,
		}
	}
	return result, nil
}
