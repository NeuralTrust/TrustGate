package gateway

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	pluginTypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type OutputTransformer struct {
}

func NewOutputTransformer() *OutputTransformer {
	return &OutputTransformer{}
}

func (ot OutputTransformer) Transform(dbGateway *gateway.Gateway) *types.GatewayDTO {
	return ot.convertGatewayToTypes(dbGateway)
}

func (ot OutputTransformer) convertGatewayToTypes(g *gateway.Gateway) *types.GatewayDTO {
	if g.RequiredPlugins == nil {
		g.RequiredPlugins = []pluginTypes.PluginConfig{}
	}

	var telemetry *types.TelemetryDTO
	if g.Telemetry != nil {
		var exporters []types.ExporterDTO
		for _, config := range g.Telemetry.Exporters {
			exporters = append(exporters, types.ExporterDTO{
				Name:     config.Name,
				Settings: config.Settings,
			})
		}
		telemetry = &types.TelemetryDTO{
			Exporters:           exporters,
			ExtraParams:         g.Telemetry.ExtraParams,
			EnablePluginTraces:  g.Telemetry.EnablePluginTraces,
			EnableRequestTraces: g.Telemetry.EnableRequestTraces,
			HeaderMapping:       g.Telemetry.HeaderMapping,
		}
	}

	var securityConfig *types.SecurityConfigDTO
	if g.SecurityConfig != nil {
		securityConfig = &types.SecurityConfigDTO{
			AllowedHosts:            g.SecurityConfig.AllowedHosts,
			AllowedHostsAreRegex:    g.SecurityConfig.AllowedHostsAreRegex,
			SSLRedirect:             g.SecurityConfig.SSLRedirect,
			SSLHost:                 g.SecurityConfig.SSLHost,
			SSLProxyHeaders:         g.SecurityConfig.SSLProxyHeaders,
			STSSeconds:              g.SecurityConfig.STSSeconds,
			STSIncludeSubdomains:    g.SecurityConfig.STSIncludeSubdomains,
			FrameDeny:               g.SecurityConfig.FrameDeny,
			CustomFrameOptionsValue: g.SecurityConfig.CustomFrameOptionsValue,
			ReferrerPolicy:          g.SecurityConfig.ReferrerPolicy,
			ContentSecurityPolicy:   g.SecurityConfig.ContentSecurityPolicy,
			ContentTypeNosniff:      g.SecurityConfig.ContentTypeNosniff,
			BrowserXSSFilter:        g.SecurityConfig.BrowserXSSFilter,
			IsDevelopment:           g.SecurityConfig.IsDevelopment,
		}
	}

	var sessionConfig *types.SessionConfigDTO
	if g.SessionConfig != nil {
		sessionConfig = &types.SessionConfigDTO{
			Enabled:       g.SessionConfig.Enabled,
			HeaderName:    g.SessionConfig.HeaderName,
			BodyParamName: g.SessionConfig.BodyParamName,
			Mapping:       g.SessionConfig.Mapping,
			TTL:           g.SessionConfig.TTL,
		}
	}

	result := &types.GatewayDTO{
		ID:              g.ID.String(),
		Name:            g.Name,
		Status:          g.Status,
		RequiredPlugins: g.RequiredPlugins,
		SecurityConfig:  securityConfig,
		Telemetry:       telemetry,
		TlS:             ot.transformClientTLSConfigToType(g.ClientTLSConfig),
		SessionConfig:   sessionConfig,
	}

	result.CreatedAt = g.CreatedAt.Format(time.RFC3339)
	result.UpdatedAt = g.UpdatedAt.Format(time.RFC3339)

	return result
}

func (ot OutputTransformer) transformClientTLSConfigToType(tls domain.ClientTLSConfig) map[string]types.ClientTLSConfigDTO {
	if len(tls) == 0 {
		return nil
	}
	result := make(map[string]types.ClientTLSConfigDTO, len(tls))
	for k, v := range tls {
		result[k] = types.ClientTLSConfigDTO{
			AllowInsecureConnections: v.AllowInsecureConnections,
			CACerts:                  v.CACerts,
			ClientCerts: types.ClientTLSCertDTO{
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
