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

package auth

import (
	"context"
	"fmt"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
)

func ensureNoOAuth2Conflict(ctx context.Context, repo domain.Repository, candidate *domain.Auth) error {
	if candidate.Type != domain.TypeOAuth2 || !candidate.Enabled || candidate.Config.OAuth2 == nil {
		return nil
	}
	existing, err := repo.FindEnabledByTypes(ctx, []domain.Type{domain.TypeOAuth2})
	if err != nil {
		return fmt.Errorf("auth: check oauth2 conflicts: %w", err)
	}
	for _, a := range existing {
		if a.ID == candidate.ID || a.GatewayID != candidate.GatewayID || a.Config.OAuth2 == nil {
			continue
		}
		if candidate.Config.OAuth2.ConflictsWith(a.Config.OAuth2) {
			return fmt.Errorf("%w: conflicts with %q (%s); scope it with a distinct audience or disable the other entry",
				domain.ErrDuplicateOAuth2, a.Name, a.ID)
		}
	}
	return nil
}
