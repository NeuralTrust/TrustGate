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

package policy

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

// MCPScopePatch is the tri-state mcp_scope of an update. Set false leaves the
// stored scope untouched, Set true with a nil Value clears it, and Set true
// with a Value replaces it after validation. A pointer alone could not tell an
// omitted field from an explicit null, and clearing a scope is a real
// operation.
type MCPScopePatch struct {
	Set   bool
	Value *domain.MCPScope
}

type UpdateInput struct {
	ID          ids.PolicyID
	GatewayID   ids.GatewayID
	Name        *string
	Description *string
	Slug        *string
	Enabled     *bool
	Priority    *int
	Parallel    *bool
	Settings    *map[string]any
	Stages      *[]domain.Stage
	Mode        *domain.Mode
	MCPScope    MCPScopePatch
}

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=policy_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Policy, error)
}

var _ Updater = (*updater)(nil)

type updater struct {
	repo         domain.Repository
	consumers    consumerdomain.Reader
	levels       LevelGuard
	registryRepo registrydomain.Repository
	registry     appplugins.Registry
	memoryCache  *cache.TTLMap
	publisher    cache.EventPublisher
	logger       *slog.Logger
	signaler     configsyncport.SnapshotSignaler
}

func NewUpdater(
	repo domain.Repository,
	consumers consumerdomain.Reader,
	levels LevelGuard,
	registryRepo registrydomain.Repository,
	registry appplugins.Registry,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
) Updater {
	return &updater{
		repo:         repo,
		consumers:    consumers,
		levels:       levels,
		registryRepo: registryRepo,
		registry:     registry,
		memoryCache:  manager.GetTTLMap(cache.PolicyTTLName),
		publisher:    publisher,
		logger:       logger,
		signaler:     signaler,
	}
}

func (u *updater) Update(ctx context.Context, in UpdateInput) (*domain.Policy, error) {
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
	if in.Description != nil {
		existing.Description = *in.Description
	}
	if in.Slug != nil {
		existing.Slug = *in.Slug
	}
	if in.Enabled != nil {
		existing.Enabled = *in.Enabled
	}
	if in.Priority != nil {
		existing.Priority = *in.Priority
	}
	if in.Parallel != nil {
		existing.Parallel = *in.Parallel
	}
	if in.Settings != nil {
		// Resolve against the plugin the settings will be validated for
		// (existing.Slug, already patched above if in.Slug was set), not the
		// slug the policy carried on load: a settings payload that also
		// changes the plugin type is for the new plugin.
		if paths := appplugins.PluginCredentialPaths(u.registry, existing.Slug); len(paths) > 0 {
			secret.ResolveSettings(*in.Settings, existing.Settings, paths)
			if err := secret.RejectMaskedSettings(*in.Settings, paths); err != nil {
				return nil, errors.Join(commonerrors.ErrValidation, err)
			}
		}
		existing.Settings = *in.Settings
	}
	if in.Stages != nil {
		existing.Stages = *in.Stages
	}
	if in.Mode != nil {
		existing.Mode = in.Mode.Normalize()
	}
	if in.MCPScope.Set {
		existing.MCPScope = in.MCPScope.Value
	}
	existing.UpdatedAt = time.Now().UTC()
	if err := existing.Validate(); err != nil {
		return nil, err
	}
	if err := validatePlugin(
		u.registry,
		existing.Slug,
		existing.Stages,
		existing.Mode,
		existing.Settings,
	); err != nil {
		return nil, err
	}
	if err := u.validateScopeAfterPatch(ctx, in, existing); err != nil {
		return nil, err
	}
	// Only an update that carried mcp_scope writes the column: echoing back the
	// value read at the top of Update would resurrect a registry that a prune
	// removed in between.
	if err := u.levels.Check(ctx, existing, func(ctx context.Context) error {
		return u.repo.Update(ctx, existing, in.MCPScope.Set)
	}); err != nil {
		return nil, err
	}
	u.memoryCache.Set(existing.ID.String(), existing)
	invalidation.GatewayData(ctx, u.publisher, u.logger, existing.GatewayID)
	if u.signaler != nil {
		u.signaler.Signal(ctx)
	}
	return existing, nil
}

// validateScopeAfterPatch revalidates the stored scope when the update can
// invalidate it. A new scope is validated in full. A slug change alone keeps
// the stored scope but points it at another plugin, so only the protocol rule
// is rechecked: the full check would refuse to rename a policy a registry
// delete had already pruned to {}.
func (u *updater) validateScopeAfterPatch(ctx context.Context, in UpdateInput, existing *domain.Policy) error {
	if in.MCPScope.Set {
		if err := validateMCPScope(ctx, u.registryRepo, u.registry, existing.GatewayID, existing.Slug, existing.MCPScope); err != nil {
			return err
		}
		return u.validateScopeReachesConsumers(ctx, existing)
	}
	if in.Slug == nil || existing.MCPScope == nil {
		return nil
	}
	if err := validateMCPScopePlugin(u.registry, existing.Slug); err != nil {
		return err
	}
	// A new slug is a new plugin, and the plugin is half of the inert-plane
	// rule, so the scope has to be weighed against the consumers again.
	return u.validateScopeReachesConsumers(ctx, existing)
}

// validateScopeReachesConsumers applies to the consumers the policy is already
// attached to the same rule the attach applies to a consumer being added.
//
// Without it the rule has a back door: attaching a tool-scoped policy to an LLM
// consumer is refused, but attaching it unscoped and then setting the scope is
// not — the same end state, and a policy that runs nowhere on that consumer
// while its screen says otherwise.
func (u *updater) validateScopeReachesConsumers(ctx context.Context, p *domain.Policy) error {
	if p.MCPScope == nil || len(p.ConsumerIDs) == 0 || u.consumers == nil {
		return nil
	}
	inertSafe := appplugins.IsInertSafe(u.registry, p.Slug)
	for _, id := range p.ConsumerIDs {
		cons, err := u.consumers.FindByID(ctx, id)
		if err != nil {
			// A consumer that cannot be read is not a scope problem, and refusing
			// the write over it would make an unrelated outage look like invalid
			// input. The attach path is still the gate for anything new.
			u.logger.WarnContext(ctx, "policy scope not checked against consumer",
				slog.String("policy_id", p.ID.String()),
				slog.String("consumer_id", id.String()),
				slog.String("error", err.Error()),
			)
			continue
		}
		if err := consumerdomain.ScopeRefusal(cons, p, inertSafe); err != nil {
			return err
		}
	}
	return nil
}
