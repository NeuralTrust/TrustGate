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
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
)

type CreateGatewayRequest struct {
	// Slug is optional; when omitted the server generates a unique random slug. If provided it must be a lowercase DNS label.
	Slug   string `json:"slug,omitempty" example:"acme-prod"`
	Domain string `json:"domain,omitempty"`
	// TenantID is optional ownership for platform (empty JWT) create-for-tenant; tenant JWTs must match or omit it.
	TenantID        string                 `json:"tenant_id,omitempty"`
	Metadata        map[string]string      `json:"metadata,omitempty"`
	Telemetry       *telemetry.Telemetry   `json:"telemetry,omitempty"`
	ClientTLSConfig domain.ClientTLSConfig `json:"client_tls,omitempty"`
	SessionConfig   *domain.SessionConfig  `json:"session_config,omitempty"`
	// Entitlements.Tier is optional; only platform admins may set it. Tenant callers sending
	// entitlements receive 422. When omitted the gateway defaults to free (or inherits sibling tier).
	Entitlements *domain.Entitlements `json:"entitlements,omitempty"`
}

// Validate checks the create request. The slug is optional: when omitted the
// server generates a unique random slug at creation time. A provided slug must
// still be a valid lowercase DNS label.
func (r CreateGatewayRequest) Validate() error {
	if r.Entitlements != nil {
		tier, err := domain.ValidateTier(r.Entitlements.Tier)
		if err != nil {
			return err
		}
		r.Entitlements.Tier = tier
	}
	if strings.TrimSpace(r.Slug) == "" {
		return nil
	}
	if !domain.IsValidSlug(domain.NormalizeSlug(r.Slug)) {
		return fmt.Errorf("slug must be a lowercase DNS label: %w", commonerrors.ErrValidation)
	}
	return nil
}
