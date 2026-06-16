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

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
)

type UpdateGatewayRequest struct {
	Name            *string                 `json:"name,omitempty"`
	Slug            *string                 `json:"slug,omitempty"`
	Status          *string                 `json:"status,omitempty"`
	Domain          *string                 `json:"domain,omitempty"`
	Metadata        map[string]string       `json:"metadata,omitempty"`
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
	if r.Slug != nil && strings.TrimSpace(*r.Slug) != "" && !domain.IsValidSlug(domain.NormalizeSlug(*r.Slug)) {
		return fmt.Errorf("slug must be a lowercase DNS label: %w", commonerrors.ErrValidation)
	}
	return nil
}
