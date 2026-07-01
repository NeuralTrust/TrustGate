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

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func referencingConsumers(ctx context.Context, consumers consumerdomain.Repository, authID ids.AuthID) ([]*consumerdomain.Consumer, error) {
	refs, err := consumers.ListByAuthID(ctx, authID)
	if err != nil {
		return nil, fmt.Errorf("auth: list consumers referencing auth: %w", err)
	}
	return refs, nil
}

func guardAuthTypeChange(ctx context.Context, consumers consumerdomain.Repository, authID ids.AuthID, newType domain.Type) error {
	refs, err := referencingConsumers(ctx, consumers, authID)
	if err != nil {
		return err
	}
	for _, c := range refs {
		if err := consumerdomain.ValidateAuthType(c.Type, c.RoutingMode, newType); err != nil {
			return fmt.Errorf("%w (referenced by consumer %q)", err, c.Slug)
		}
	}
	return nil
}

func guardAuthDisable(ctx context.Context, consumers consumerdomain.Repository, auths domain.Repository, authID ids.AuthID) error {
	refs, err := referencingConsumers(ctx, consumers, authID)
	if err != nil {
		return err
	}
	for _, c := range refs {
		switch {
		case c.RoutingMode == consumerdomain.RoutingModeRoleBased:
			return fmt.Errorf(
				"%w: auth is the only identity provider of role_based consumer %q; reassign it before disabling",
				commonerrors.ErrConflict, c.Slug,
			)
		case c.Type == consumerdomain.TypeMCP:
			hasAlternative, err := consumerHasOtherUsableAuth(ctx, auths, c, authID)
			if err != nil {
				return err
			}
			if !hasAlternative {
				return fmt.Errorf(
					"%w: auth is the only usable identity provider of MCP consumer %q; reassign it before disabling",
					commonerrors.ErrConflict, c.Slug,
				)
			}
		}
	}
	return nil
}

func consumerHasOtherUsableAuth(ctx context.Context, auths domain.Repository, c *consumerdomain.Consumer, excluded ids.AuthID) (bool, error) {
	if len(c.AuthIDs) <= 1 {
		return false, nil
	}
	siblings, err := auths.FindByIDs(ctx, c.GatewayID, c.AuthIDs)
	if err != nil {
		return false, fmt.Errorf("auth: load consumer auths: %w", err)
	}
	for _, s := range siblings {
		if s.ID == excluded || !s.Enabled {
			continue
		}
		if consumerdomain.ValidateAuthType(c.Type, c.RoutingMode, s.Type) == nil {
			return true, nil
		}
	}
	return false, nil
}

func detachAuthFromConsumers(ctx context.Context, consumers consumerdomain.Repository, authID ids.AuthID) error {
	refs, err := referencingConsumers(ctx, consumers, authID)
	if err != nil {
		return err
	}
	for _, c := range refs {
		if err := consumers.DetachAuth(ctx, c.ID, authID); err != nil {
			return fmt.Errorf("auth: detach from consumer %q: %w", c.Slug, err)
		}
	}
	return nil
}

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
