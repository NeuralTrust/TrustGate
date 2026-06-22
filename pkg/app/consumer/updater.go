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
	"context"
	"fmt"
	"log/slog"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

type UpdateInput struct {
	ID            ids.ConsumerID
	GatewayID     ids.GatewayID
	Name          *string
	Type          *domain.Type
	RoutingMode   *domain.RoutingMode
	LBConfig      *domain.LBConfig
	Headers       *map[string]string
	Active        *bool
	Fallback      *domain.Fallback
	ModelPolicies *domain.ModelPolicies
	Toolkit       *domain.Toolkit
	FailMode      *domain.FailMode
}

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=consumer_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Consumer, error)
}

var _ Updater = (*updater)(nil)

type updater struct {
	repo        domain.Repository
	authRepo    authdomain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
}

func NewUpdater(
	repo domain.Repository,
	authRepo authdomain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
) Updater {
	return &updater{
		repo:        repo,
		authRepo:    authRepo,
		memoryCache: manager.GetTTLMap(cache.ConsumerTTLName),
		publisher:   publisher,
		logger:      logger,
	}
}

func (u *updater) Update(ctx context.Context, in UpdateInput) (*domain.Consumer, error) {
	existing, err := u.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if !in.GatewayID.IsNil() && in.GatewayID != existing.GatewayID {
		return nil, domain.ErrInvalidGatewayID
	}
	if in.Name != nil {
		existing.Name = *in.Name
	}
	previousType := existing.Type
	if in.Type != nil && *in.Type != existing.Type {
		existing.Type = *in.Type
		existing.MCP = nil
	}
	previousMode := existing.RoutingMode
	if in.RoutingMode != nil {
		existing.RoutingMode = *in.RoutingMode
	}
	if in.LBConfig != nil {
		resolveLBConfigSecrets(in.LBConfig, existing.LBConfig)
		existing.LBConfig = in.LBConfig
	}
	if in.Headers != nil {
		existing.Headers = *in.Headers
	}
	if in.Active != nil {
		existing.Active = *in.Active
	}
	if in.Fallback != nil {
		existing.Fallback = in.Fallback
	}
	if in.ModelPolicies != nil {
		existing.ModelPolicies = *in.ModelPolicies
	}
	applyMCPPolicyUpdate(existing, in)
	if previousMode != existing.RoutingMode {
		cleanIncompatibleModeConfig(existing)
	}
	existing.UpdatedAt = time.Now().UTC()
	if err := validateRegistryRefsAssociated(existing); err != nil {
		return nil, err
	}
	if err := existing.Validate(); err != nil {
		return nil, err
	}
	if err := u.revalidateAuthsForTransition(ctx, existing, previousType, previousMode); err != nil {
		return nil, err
	}
	if err := u.repo.Update(ctx, existing); err != nil {
		return nil, err
	}
	u.memoryCache.Set(existing.ID.String(), existing)
	publishGatewayDataInvalidation(ctx, u.publisher, u.logger, existing.GatewayID)
	return existing, nil
}

func (u *updater) revalidateAuthsForTransition(
	ctx context.Context,
	c *domain.Consumer,
	previousType domain.Type,
	previousMode domain.RoutingMode,
) error {
	toMCP := c.Type == domain.TypeMCP && previousType != domain.TypeMCP
	toRoleBased := c.RoutingMode == domain.RoutingModeRoleBased && previousMode != domain.RoutingModeRoleBased
	if (!toMCP && !toRoleBased) || len(c.AuthIDs) == 0 {
		return nil
	}
	auths, err := u.authRepo.FindByIDs(ctx, c.GatewayID, c.AuthIDs)
	if err != nil {
		return err
	}
	if len(auths) != len(c.AuthIDs) {
		return fmt.Errorf("%w: consumer references %d auth(s) but %d were found in its gateway",
			commonerrors.ErrConflict, len(c.AuthIDs), len(auths))
	}
	for _, au := range auths {
		if err := domain.ValidateAuthType(c.Type, c.RoutingMode, au.Type); err != nil {
			return err
		}
	}
	return nil
}

func applyMCPPolicyUpdate(existing *domain.Consumer, in UpdateInput) {
	if in.Toolkit == nil && in.FailMode == nil {
		return
	}
	if existing.MCP == nil {
		existing.MCP = &domain.MCPPolicy{}
	}
	policy := existing.MCP
	if in.Toolkit != nil {
		policy.Toolkit = *in.Toolkit
	}
	if in.FailMode != nil {
		policy.FailMode = *in.FailMode
	}
}

func validateRegistryRefsAssociated(c *domain.Consumer) error {
	if c.RoutingMode == domain.RoutingModeRoleBased {
		return nil
	}
	associated := make(map[ids.RegistryID]struct{}, len(c.RegistryIDs))
	for _, id := range c.RegistryIDs {
		associated[id] = struct{}{}
	}
	if c.Fallback != nil {
		for _, id := range c.Fallback.Chain {
			if _, ok := associated[id]; !ok {
				return fmt.Errorf("%w: fallback chain registry %s is not associated with the consumer",
					registrydomain.ErrInvalidRegistryID, id)
			}
		}
	}
	for id := range c.ModelPolicies {
		if _, ok := associated[id]; !ok {
			return fmt.Errorf("%w: model_policies registry %s is not associated with the consumer",
				registrydomain.ErrInvalidRegistryID, id)
		}
	}
	if c.LBConfig != nil {
		for _, member := range c.LBConfig.Members {
			if _, ok := associated[member.RegistryID]; !ok {
				return fmt.Errorf("%w: lb_config member registry %s is not associated with the consumer",
					registrydomain.ErrInvalidRegistryID, member.RegistryID)
			}
		}
	}
	for _, e := range c.Toolkit() {
		if _, ok := associated[e.RegistryID]; !ok {
			return fmt.Errorf("%w: toolkit registry %s is not associated with the consumer",
				registrydomain.ErrInvalidRegistryID, e.RegistryID)
		}
	}
	return nil
}

func cleanIncompatibleModeConfig(c *domain.Consumer) {
	switch c.RoutingMode {
	case domain.RoutingModeRoleBased:
		c.RegistryIDs = nil
		c.Fallback = nil
		c.LBConfig = nil
		c.ModelPolicies = nil
		c.MCP = nil
	case domain.RoutingModeInline:
		c.RoleIDs = nil
	}
}

func resolveLBConfigSecrets(next, prev *domain.LBConfig) {
	if next == nil || next.EmbeddingConfig == nil {
		return
	}
	if prev == nil {
		next.EmbeddingConfig.ResolveSecretsFrom(nil)
		return
	}
	next.EmbeddingConfig.ResolveSecretsFrom(prev.EmbeddingConfig)
}
