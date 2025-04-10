package gateway

import (
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type OutputTransformer struct {
}

func NewOutputTransformer() *OutputTransformer {
	return &OutputTransformer{}
}

func (ot OutputTransformer) Transform(dbGateway *gateway.Gateway) (*types.Gateway, error) {
	if dbGateway.RequiredPlugins == nil {
		dbGateway.RequiredPlugins = []types.PluginConfig{}
	}

	var exporters []types.Exporter
	var telemetry *types.Telemetry
	if dbGateway.Telemetry != nil {
		for _, config := range dbGateway.Telemetry.Exporters {
			providerConfig := types.Exporter{
				Name:     config.Name,
				Settings: config.Settings,
			}
			exporters = append(exporters, providerConfig)
		}
		telemetry = &types.Telemetry{
			Exporters: exporters,
		}
	}

	var securityConfig *types.SecurityConfig
	if dbGateway.SecurityConfig != nil {
		securityConfig = &types.SecurityConfig{
			AllowedHosts:            dbGateway.SecurityConfig.AllowedHosts,
			AllowedHostsAreRegex:    dbGateway.SecurityConfig.AllowedHostsAreRegex,
			SSLRedirect:             dbGateway.SecurityConfig.SSLRedirect,
			SSLHost:                 dbGateway.SecurityConfig.SSLHost,
			SSLProxyHeaders:         dbGateway.SecurityConfig.SSLProxyHeaders,
			STSSeconds:              dbGateway.SecurityConfig.STSSeconds,
			STSIncludeSubdomains:    dbGateway.SecurityConfig.STSIncludeSubdomains,
			FrameDeny:               dbGateway.SecurityConfig.FrameDeny,
			CustomFrameOptionsValue: dbGateway.SecurityConfig.CustomFrameOptionsValue,
			ReferrerPolicy:          dbGateway.SecurityConfig.ReferrerPolicy,
			ContentSecurityPolicy:   dbGateway.SecurityConfig.ContentSecurityPolicy,
			ContentTypeNosniff:      dbGateway.SecurityConfig.ContentTypeNosniff,
			BrowserXSSFilter:        dbGateway.SecurityConfig.BrowserXSSFilter,
			IsDevelopment:           dbGateway.SecurityConfig.IsDevelopment,
		}
	}

	return &types.Gateway{
		ID:              dbGateway.ID.String(),
		Name:            dbGateway.Name,
		Subdomain:       dbGateway.Subdomain,
		Status:          dbGateway.Status,
		RequiredPlugins: dbGateway.RequiredPlugins,
		Telemetry:       telemetry,
		SecurityConfig:  securityConfig,
		CreatedAt:       dbGateway.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       dbGateway.UpdatedAt.Format(time.RFC3339),
	}, nil
}
