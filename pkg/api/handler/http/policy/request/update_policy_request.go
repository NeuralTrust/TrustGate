package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

type UpdatePolicyRequest struct {
	Name    string          `json:"name"`
	Plugins []PluginRequest `json:"plugins,omitempty"`
}

func (r UpdatePolicyRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Name) > 255 {
		return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdatePolicyRequest) ToPlugins() domain.Plugins {
	out := make(domain.Plugins, 0, len(r.Plugins))
	for _, p := range r.Plugins {
		out = append(out, p.ToDomain())
	}
	return out
}
