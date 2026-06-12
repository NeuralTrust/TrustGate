package registry

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
)

type LLMTarget struct {
	Provider        string         `json:"provider"`
	ProviderOptions map[string]any `json:"provider_options,omitempty"`
	Auth            *TargetAuth    `json:"auth,omitempty"`
	HealthChecks    *HealthChecks  `json:"health_checks,omitempty"`
}

func (t *LLMTarget) Validate() error {
	if t == nil {
		return fmt.Errorf("%w: llm_target is required for LLM registries", ErrInvalidRegistry)
	}
	if t.Provider == "" {
		return fmt.Errorf("%w: provider is required", ErrInvalidRegistry)
	}
	if !providers.IsValidProvider(t.Provider) {
		return fmt.Errorf("%w: unsupported provider %q", ErrInvalidRegistry, t.Provider)
	}
	if err := providers.ValidateProviderOptions(t.Provider, t.ProviderOptions); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRegistry, err)
	}
	if t.Auth == nil {
		return fmt.Errorf("%w: auth is required", ErrInvalidRegistry)
	}
	if err := t.Auth.Validate(); err != nil {
		return err
	}
	if t.HealthChecks != nil {
		if err := t.HealthChecks.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (t *LLMTarget) ResolveSecretsFrom(prev *LLMTarget) {
	if t == nil || prev == nil {
		return
	}
	t.Auth.ResolveSecretsFrom(prev.Auth)
}
