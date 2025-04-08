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

	var configs []types.ProviderConfig
	var telemetry *types.Telemetry
	if dbGateway.Telemetry != nil {
		for _, config := range dbGateway.Telemetry.Configs {
			providerConfig := types.ProviderConfig{
				Name:     config.Name,
				Settings: config.Settings,
			}
			configs = append(configs, providerConfig)
		}
		telemetry = &types.Telemetry{
			Configs: configs,
		}
	}

	if dbGateway.Telemetry != nil {

	}
	return &types.Gateway{
		ID:              dbGateway.ID.String(),
		Name:            dbGateway.Name,
		Subdomain:       dbGateway.Subdomain,
		Status:          dbGateway.Status,
		RequiredPlugins: dbGateway.RequiredPlugins,
		Telemetry:       telemetry,
		CreatedAt:       dbGateway.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       dbGateway.UpdatedAt.Format(time.RFC3339),
	}, nil
}
