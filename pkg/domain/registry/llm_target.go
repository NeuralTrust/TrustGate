// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package registry

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
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
	if !provider.IsValid(t.Provider) {
		return fmt.Errorf("%w: unsupported provider %q", ErrInvalidRegistry, t.Provider)
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
