package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

type CreatePolicyRequest struct {
	Name    string          `json:"name"`
	Plugins []PluginRequest `json:"plugins,omitempty"`
}

type PluginRequest struct {
	ID       string                 `json:"id,omitempty"`
	Name     string                 `json:"name"`
	Enabled  bool                   `json:"enabled"`
	Stage    string                 `json:"stage"`
	Priority int                    `json:"priority"`
	Parallel bool                   `json:"parallel,omitempty"`
	Settings map[string]interface{} `json:"settings,omitempty"`
}

func (r CreatePolicyRequest) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
	}
	if len(r.Name) > 255 {
		return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r CreatePolicyRequest) ToPlugins() domain.Plugins {
	out := make(domain.Plugins, 0, len(r.Plugins))
	for _, p := range r.Plugins {
		out = append(out, p.ToDomain())
	}
	return out
}

func (p PluginRequest) ToDomain() domain.Plugin {
	return domain.Plugin{
		ID:       p.ID,
		Name:     p.Name,
		Enabled:  p.Enabled,
		Stage:    domain.Stage(p.Stage),
		Priority: p.Priority,
		Parallel: p.Parallel,
		Settings: p.Settings,
	}
}
