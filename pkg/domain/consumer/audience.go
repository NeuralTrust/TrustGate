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

package consumer

import (
	"fmt"
	"slices"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// Audience is who a consumer serves: an application, or users through the LLM
// Store.
type Audience string

const (
	AudienceApplication Audience = "application"
	AudiencePersonal    Audience = "personal"
)

// ParseAudience maps a stored or requested audience onto its in-memory form,
// where an application consumer holds the empty audience.
func ParseAudience(s string) (Audience, error) {
	switch Audience(s) {
	case "", AudienceApplication, AudiencePersonal:
		return Audience(s).canonical(), nil
	}
	return "", fmt.Errorf("%w: %q", ErrInvalidAudience, s)
}

func (a Audience) canonical() Audience {
	if a == AudienceApplication {
		return ""
	}
	return a
}

// IsPersonal reports whether c serves users through the LLM Store.
func (c *Consumer) IsPersonal() bool {
	return c.Audience == AudiencePersonal
}

// AudienceName returns c's audience, application when it was stored without one.
func (c *Consumer) AudienceName() Audience {
	if c.Audience == "" {
		return AudienceApplication
	}
	return c.Audience
}

// ValidateRegistryDetach refuses, with ErrPersonalNoDefault, to take from a
// personal consumer the registry that carries its last primary default model,
// whether by a detach or by deleting the registry. A consumer that has no
// primary default already is never refused, so it can still be cleaned up.
func (c *Consumer) ValidateRegistryDetach(registryID ids.RegistryID) error {
	if c.IsPersonal() && c.hasPrimaryDefault(ids.RegistryID{}) && !c.hasPrimaryDefault(registryID) {
		return fmt.Errorf("%w: registry %s carries the last primary default model of personal consumer %s; set a default on another primary registry first",
			ErrPersonalNoDefault, registryID, c.ID)
	}
	return nil
}

func (c *Consumer) validatePersonal() error {
	if !c.IsPersonal() {
		return nil
	}
	if c.Type != TypeLLM {
		return fmt.Errorf("%w: only LLM consumers can be personal", ErrInvalidAudience)
	}
	if !c.hasPrimaryDefault(ids.RegistryID{}) {
		return ErrPersonalNoDefault
	}
	return nil
}

func (c *Consumer) hasPrimaryDefault(excluded ids.RegistryID) bool {
	fallback := c.ActiveFallbackChain()
	for _, id := range c.RegistryIDs {
		if id == excluded || slices.Contains(fallback, id) {
			continue
		}
		if c.ModelPolicies[id].Default != "" {
			return true
		}
	}
	return false
}
