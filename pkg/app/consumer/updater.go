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

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

type UpdateInput struct {
	ID        ids.ConsumerID
	GatewayID ids.GatewayID
	Name      *string
	Type      *domain.Type
	LBConfig  *domain.LBConfig
	Headers   *map[string]string
	Active    *bool
	Fallback  *domain.Fallback
	// Registries replaces the whole registry association set. A nil value keeps
	// the associations the consumer already has.
	Registries *domain.RegistryBindings
	// Auths replaces the whole auth association set. A nil value keeps the
	// associations the consumer already has.
	Auths         *[]ids.AuthID
	ModelPolicies *domain.ModelPolicies
	Toolkit       *domain.Toolkit
	FailMode      *domain.FailMode
	// Identity replaces who the consumer acts for. A nil value keeps it.
	Identity *domain.Identity
	// AuthBinding replaces the whole binding. A nil value keeps it.
	AuthBinding *domain.AuthBinding
}

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=consumer_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Consumer, error)
}

var _ Updater = (*updater)(nil)

type updater struct {
	repo         domain.Repository
	registryRepo registrydomain.Repository
	authRepo     authdomain.Repository
	memoryCache  *cache.TTLMap
	publisher    cache.EventPublisher
	logger       *slog.Logger
	signaler     configsyncport.SnapshotSignaler
}

func NewUpdater(
	repo domain.Repository,
	registryRepo registrydomain.Repository,
	authRepo authdomain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
) Updater {
	return &updater{
		repo:         repo,
		registryRepo: registryRepo,
		authRepo:     authRepo,
		memoryCache:  manager.GetTTLMap(cache.ConsumerTTLName),
		publisher:    publisher,
		logger:       logger,
		signaler:     signaler,
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
	previousIdentity := existing.Identity
	if in.Identity != nil {
		existing.Identity = *in.Identity
	}
	if in.AuthBinding != nil {
		existing.AuthBinding = *in.AuthBinding
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
	if in.Registries != nil {
		existing.RegistryIDs = in.Registries.IDs
		existing.RegistryWeights = in.Registries.Weights
	}
	previousAuthIDs := existing.AuthIDs
	if in.Auths != nil {
		existing.AuthIDs = *in.Auths
	}
	existing.UpdatedAt = time.Now().UTC()
	if err := validateRegistryRefsAssociated(existing); err != nil {
		return nil, err
	}
	if err := existing.Validate(); err != nil {
		return nil, err
	}
	if in.Registries != nil {
		if err := ensureRegistriesInGateway(ctx, u.registryRepo, existing.GatewayID, existing.RegistryIDs); err != nil {
			return nil, err
		}
	}
	if err := u.revalidateAuthsForTransition(ctx, existing, previousType, previousIdentity, in.Auths != nil); err != nil {
		return nil, err
	}
	u.warnDefaultIdPWidening(ctx, existing, previousAuthIDs, in.Auths)
	if err := u.repo.Update(ctx, existing, requestedRegistryBindings(existing, in.Registries), requestedAuthLinks(existing, in.Auths)); err != nil {
		return nil, err
	}
	u.memoryCache.Set(existing.ID.String(), existing)
	invalidation.GatewayData(ctx, u.publisher, u.logger, existing.GatewayID)
	if u.signaler != nil {
		u.signaler.Signal(ctx)
	}
	return existing, nil
}

// requestedRegistryBindings returns the association set the repository must
// persist, or nil when the caller did not ask to change it. It reads the
// validated aggregate rather than the input.
func requestedRegistryBindings(c *domain.Consumer, requested *domain.RegistryBindings) *domain.RegistryBindings {
	if requested == nil {
		return nil
	}
	return &domain.RegistryBindings{IDs: c.RegistryIDs, Weights: c.RegistryWeights}
}

func requestedAuthLinks(c *domain.Consumer, requested *[]ids.AuthID) *[]ids.AuthID {
	if requested == nil {
		return nil
	}
	authIDs := c.AuthIDs
	return &authIDs
}

// warnDefaultIdPWidening records the one auth replacement that widens who can
// get in: detaching every auth from a consumer whose users sign in moves it
// from "only the identity provider it pinned" to "any built-in default-IdP
// login", because an empty auth binding is what makes the default usable. It
// is a legitimate admin action and stays inside the tenant, so it is logged
// rather than refused (RUN-1501).
func (u *updater) warnDefaultIdPWidening(
	ctx context.Context,
	c *domain.Consumer,
	previousAuthIDs []ids.AuthID,
	requested *[]ids.AuthID,
) {
	if requested == nil || len(*requested) != 0 || !c.Identity.PlatformUsers() || len(previousAuthIDs) == 0 {
		return
	}
	previous, err := u.authRepo.FindByIDs(ctx, c.GatewayID, previousAuthIDs)
	if err != nil {
		return
	}
	for _, au := range previous {
		if au.Type != authdomain.TypeOAuth2 {
			continue
		}
		u.logger.WarnContext(ctx,
			"consumer detached its identity provider: its users now sign in through the built-in default identity provider",
			"consumer_id", c.ID.String(),
			"gateway_id", c.GatewayID.String(),
			"detached_auth_id", au.ID.String(),
		)
		return
	}
}

func (u *updater) revalidateAuthsForTransition(
	ctx context.Context,
	c *domain.Consumer,
	previousType domain.Type,
	previousIdentity domain.Identity,
	authsReplaced bool,
) error {
	toMCP := c.Type == domain.TypeMCP && previousType != domain.TypeMCP
	identityChanged := c.Identity != previousIdentity
	if (!toMCP && !identityChanged && !authsReplaced) || len(c.AuthIDs) == 0 {
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
		if err := domain.ValidateAuthConfig(c, au); err != nil {
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
