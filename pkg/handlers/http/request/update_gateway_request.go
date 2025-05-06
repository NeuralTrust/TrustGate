package request

import (
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type UpdateGatewayRequest struct {
	Name            *string                           `json:"name,omitempty"`
	Status          *string                           `json:"status,omitempty"`
	RequiredPlugins []types.PluginConfig              `json:"required_plugins,omitempty"`
	Telemetry       *TelemetryRequest                 `json:"telemetry"`
	TlS             map[string]ClientTLSConfigRequest `json:"client_tls"`
	SecurityConfig  *SecurityConfigRequest            `json:"security_config"`
}

func (r *UpdateGatewayRequest) Validate() error {
	return validateTls(r.TlS)
}
