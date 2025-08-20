package gateway

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type OutputTransformer struct {
}

func NewOutputTransformer() *OutputTransformer {
	return &OutputTransformer{}
}

func (ot OutputTransformer) Transform(dbGateway *gateway.Gateway) *types.Gateway {
	return ot.convertGatewayToTypes(dbGateway)
}

func (ot OutputTransformer) convertGatewayToTypes(g *gateway.Gateway) *types.Gateway {
	if g.RequiredPlugins == nil {
		g.RequiredPlugins = []types.PluginConfig{}
	}

	var telemetry *types.Telemetry
	if g.Telemetry != nil {
		var exporters []types.Exporter
		for _, config := range g.Telemetry.Exporters {
			exporters = append(exporters, types.Exporter{
				Name:     config.Name,
				Settings: config.Settings,
			})
		}
		telemetry = &types.Telemetry{
			Exporters:           exporters,
			ExtraParams:         g.Telemetry.ExtraParams,
			EnablePluginTraces:  g.Telemetry.EnablePluginTraces,
			EnableRequestTraces: g.Telemetry.EnableRequestTraces,
			HeaderMapping:       g.Telemetry.HeaderMapping,
		}
	}

	var securityConfig *types.SecurityConfig
	if g.SecurityConfig != nil {
		securityConfig = &types.SecurityConfig{
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

	var sessionConfig *types.SessionConfig
	if g.SessionConfig != nil {
		sessionConfig = &types.SessionConfig{
			Enabled:       g.SessionConfig.Enabled,
			HeaderName:    g.SessionConfig.HeaderName,
			BodyParamName: g.SessionConfig.BodyParamName,
			Mapping:       g.SessionConfig.Mapping,
			TTL:           g.SessionConfig.TTL,
		}
	}

	result := &types.Gateway{
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

func (ot OutputTransformer) transformClientTLSConfigToType(tls domain.ClientTLSConfig) map[string]types.ClientTLSConfig {
	if len(tls) == 0 {
		return nil
	}
	result := make(map[string]types.ClientTLSConfig, len(tls))
	for k, v := range tls {
		result[k] = types.ClientTLSConfig{
			AllowInsecureConnections: v.AllowInsecureConnections,
			CACerts:                  v.CACerts,
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
