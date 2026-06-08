package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
)

type UpdateGatewayRequest struct {
	Name            *string                 `json:"name,omitempty"`
	Status          *string                 `json:"status,omitempty"`
	Telemetry       *telemetry.Telemetry    `json:"telemetry,omitempty"`
	ClientTLSConfig *domain.ClientTLSConfig `json:"client_tls,omitempty"`
	SessionConfig   *domain.SessionConfig   `json:"session_config,omitempty"`
}

func (r UpdateGatewayRequest) Validate() error {
	if r.Name != nil {
		if strings.TrimSpace(*r.Name) == "" {
			return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
		}
		if len(*r.Name) > 255 {
			return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
		}
	}
	return nil
}
