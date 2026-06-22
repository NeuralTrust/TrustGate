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

package request

import (
	"fmt"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type UpdateRegistryRequest struct {
	Name            *string              `json:"name,omitempty"`
	Enabled         *bool                `json:"enabled,omitempty"`
	Provider        *string              `json:"provider,omitempty"`
	ProviderOptions *map[string]any      `json:"provider_options,omitempty"`
	Description     *string              `json:"description,omitempty"`
	Auth            *TargetAuthRequest   `json:"auth,omitempty"`
	HealthChecks    *HealthChecksRequest `json:"health_checks,omitempty"`
	MCPTarget       *MCPTargetRequest    `json:"mcp_target,omitempty"`
}

func (r UpdateRegistryRequest) Validate() error {
	if r.Name != nil {
		if strings.TrimSpace(*r.Name) == "" {
			return fmt.Errorf("name is required: %w", commonerrors.ErrValidation)
		}
		if len(*r.Name) > 255 {
			return fmt.Errorf("name too long (max 255): %w", commonerrors.ErrValidation)
		}
	}
	if r.Provider != nil && strings.TrimSpace(*r.Provider) == "" {
		return fmt.Errorf("provider is required: %w", commonerrors.ErrValidation)
	}
	return nil
}

func (r UpdateRegistryRequest) ToAuth() *domain.TargetAuth {
	return r.Auth.ToDomain()
}

func (r UpdateRegistryRequest) ToHealthChecks() *domain.HealthChecks {
	return r.HealthChecks.ToDomain()
}

func (r UpdateRegistryRequest) ToMCPTarget() *domain.MCPTarget {
	return r.MCPTarget.ToDomain()
}
