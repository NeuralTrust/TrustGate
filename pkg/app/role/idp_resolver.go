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

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
)

type IDPResolver interface {
	ResolveIDPRoles(ctx context.Context, roles []*domain.Role, claims map[string]any) ([]ids.RoleID, error)
}

var _ IDPResolver = (*idpResolver)(nil)

type idpResolver struct{}

func NewIDPResolver() IDPResolver {
	return idpResolver{}
}

func (r idpResolver) ResolveIDPRoles(_ context.Context, roles []*domain.Role, claims map[string]any) ([]ids.RoleID, error) {
	roleIDs := make([]ids.RoleID, 0, len(roles))
	for _, gatewayRole := range roles {
		if gatewayRole == nil || len(gatewayRole.IDPMapping) == 0 {
			continue
		}
		mapping, err := domain.ParseIDPMapping(gatewayRole.IDPMapping)
		if err != nil {
			return nil, err
		}
		if mapping.Matches(claims) {
			roleIDs = append(roleIDs, gatewayRole.ID)
		}
	}
	return roleIDs, nil
}
