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
	"strings"
	"sync/atomic"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
)

// A managed registry is an LLM registry NeuralTrust runs for a tenant (the
// built-in OpenAI registry every new organization gets). Its credentials are
// NeuralTrust's own: they come from this process's environment when a request
// is sent, so they are never stored, never put in a config snapshot and never
// returned by the admin API. Only the platform creates, changes or deletes a
// managed registry; a tenant can use it, not edit it.

// ErrManaged is a tenant asking to create, change or delete a managed registry.
var ErrManaged = fmt.Errorf("registry: managed by NeuralTrust and cannot be changed: %w", commonerrors.ErrForbidden)

// managedProviders are the providers NeuralTrust can supply credentials for.
var managedProviders = map[string]bool{
	provider.OpenAI: true,
}

// managedAPIKeys holds NeuralTrust's API key per provider code. It is set once
// at startup from the configuration (see SetManagedAPIKeys) and only read
// afterwards.
var managedAPIKeys atomic.Pointer[map[string]string]

// SetManagedAPIKeys records the API keys NeuralTrust supplies for managed
// registries, by provider code. Blank keys are dropped, so a provider without
// one reads as unconfigured and its managed registries send no credentials.
func SetManagedAPIKeys(keys map[string]string) {
	clean := make(map[string]string, len(keys))
	for code, key := range keys {
		if key = strings.TrimSpace(key); key != "" {
			clean[code] = key
		}
	}
	managedAPIKeys.Store(&clean)
}

func managedAPIKey(providerCode string) string {
	keys := managedAPIKeys.Load()
	if keys == nil {
		return ""
	}
	return (*keys)[providerCode]
}

// IsManagedProvider reports whether NeuralTrust can run a managed registry for
// the provider.
func IsManagedProvider(code string) bool {
	return managedProviders[code]
}

// NewManagedLLMRegistry builds an enabled managed LLM registry. The target
// names the provider only: NeuralTrust supplies the credentials.
func NewManagedLLMRegistry(
	gatewayID ids.GatewayID,
	name, description string,
	target *LLMTarget,
) (*Registry, error) {
	id, err := ids.NewV7[ids.RegistryKind]()
	if err != nil {
		return nil, fmt.Errorf("registry: generate uuid: %w", err)
	}
	now := time.Now().UTC()
	b := &Registry{
		ID:          id,
		GatewayID:   gatewayID,
		Name:        name,
		Type:        TypeLLM,
		Enabled:     true,
		Managed:     true,
		Description: description,
		LLMTarget:   target,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// EffectiveAuth is the credentials a request to the registry's provider is
// sent with: NeuralTrust's own for a managed registry (nil when this process
// has none for its provider), the stored ones otherwise. Use it wherever the
// gateway calls the provider; use Auth for what is stored or shown.
func (b *Registry) EffectiveAuth() *TargetAuth {
	if b == nil {
		return nil
	}
	if !b.Managed {
		return b.Auth()
	}
	key := managedAPIKey(b.Provider())
	if key == "" {
		return nil
	}
	return &TargetAuth{Type: AuthTypeAPIKey, APIKey: &APIKeyAuth{APIKey: key}}
}

// validateManagedLLM holds a managed registry to what NeuralTrust can run: a
// provider it has credentials for, no credentials of its own, and the
// provider's own host, so NeuralTrust's key is only ever sent there.
func (b *Registry) validateManagedLLM() error {
	t := b.LLMTarget
	if t == nil {
		return fmt.Errorf("%w: llm_target is required for LLM registries", ErrInvalidRegistry)
	}
	if !IsManagedProvider(t.Provider) {
		return fmt.Errorf("%w: provider %q cannot be managed", ErrInvalidRegistry, t.Provider)
	}
	if t.Auth != nil {
		return fmt.Errorf("%w: a managed registry carries no credentials", ErrInvalidRegistry)
	}
	if baseURL, _ := t.ProviderOptions["base_url"].(string); strings.TrimSpace(baseURL) != "" {
		return fmt.Errorf("%w: a managed registry cannot set provider_options.base_url", ErrInvalidRegistry)
	}
	return t.validate(false)
}
