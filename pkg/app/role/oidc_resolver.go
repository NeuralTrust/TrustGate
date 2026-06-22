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

package role

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
)

type OIDCResolver interface {
	ResolveOIDCRoles(ctx context.Context, roles []*domain.Role, claims map[string]any) ([]ids.RoleID, error)
}

var _ OIDCResolver = (*oidcResolver)(nil)

type oidcResolver struct{}

func NewOIDCResolver() OIDCResolver {
	return oidcResolver{}
}

func (r oidcResolver) ResolveOIDCRoles(_ context.Context, roles []*domain.Role, claims map[string]any) ([]ids.RoleID, error) {
	roleIDs := make([]ids.RoleID, 0, len(roles))
	for _, gatewayRole := range roles {
		if gatewayRole == nil || len(gatewayRole.OIDCMapping) == 0 {
			continue
		}
		mapping, err := domain.ParseOIDCMapping(gatewayRole.OIDCMapping)
		if err != nil {
			return nil, err
		}
		if mapping.Matches(claims) {
			roleIDs = append(roleIDs, gatewayRole.ID)
		}
	}
	return roleIDs, nil
}
