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

package registry

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

//go:generate mockery --name=Deleter --dir=. --output=./mocks --filename=registry_deleter_mock.go --case=underscore --with-expecter
type Deleter interface {
	Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID) error
}

var _ Deleter = (*deleter)(nil)

type DependentCleaner interface {
	DeleteByRegistry(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) error
}

type DeleterOption func(*deleter)

// WithDependentCleaner registers a cleanup that runs before the registry row is
// removed, each cleaner in its own transaction.
//
// RUN-1501: this is not the seam for routing references. A cleaner commits
// separately from the delete, so a later failure leaves its rows gone and the
// registry present; the consumer routing prune therefore hangs off
// registryrepo.WithDeleteHook, which runs inside the delete's own transaction.
// The Store grant cleanup stays here because storeaccess.Repository exposes no
// transaction-scoped DeleteByRegistry, and giving it one would widen this change
// into the store-access repository and its DI for no behavioural gain.
func WithDependentCleaner(c DependentCleaner) DeleterOption {
	return func(d *deleter) {
		if c != nil {
			d.cleaners = append(d.cleaners, c)
		}
	}
}

type deleter struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
	cleaners    []DependentCleaner
}

func NewDeleter(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
	opts ...DeleterOption,
) Deleter {
	d := &deleter{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.RegistryTTLName),
		publisher:   publisher,
		logger:      logger,
		signaler:    signaler,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(d)
		}
	}
	return d
}

func (d *deleter) Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.RegistryID) error {
	existing, err := d.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if existing.GatewayID != gatewayID {
		return domain.ErrNotFound
	}
	for _, cleaner := range d.cleaners {
		if err := cleaner.DeleteByRegistry(ctx, gatewayID, id); err != nil {
			return fmt.Errorf("clean registry dependency: %w", err)
		}
	}
	report, err := d.repo.Delete(ctx, gatewayID, id)
	if err != nil {
		return err
	}
	d.logPrunedRouting(ctx, gatewayID, id, report)
	d.memoryCache.Delete(id.String())
	invalidation.Registry(ctx, d.publisher, d.logger, existing.GatewayID, existing.ID)
	if d.signaler != nil {
		d.signaler.Signal(ctx)
	}
	return nil
}

// RUN-1501: the delete answers 204 and rewrites four JSONB columns across every
// consumer of the gateway, so without this line an operator has no record of
// which consumers lost a pool member, a smart-routing ladder, a fallback step or
// a toolkit entry. It runs after repo.Delete returns, so it only reports writes
// that actually committed.
func (d *deleter) logPrunedRouting(
	ctx context.Context,
	gatewayID ids.GatewayID,
	id ids.RegistryID,
	report domain.PruneReport,
) {
	if d.logger == nil || report.Empty() {
		return
	}
	for _, prune := range report.Consumers {
		d.logger.InfoContext(ctx, "registry delete pruned consumer routing",
			slog.String("gateway_id", gatewayID.String()),
			slog.String("registry_id", id.String()),
			slog.String("consumer_id", prune.ConsumerID.String()),
			slog.Any("rewritten", prune.Rewritten),
			slog.Any("nulled", prune.Nulled),
		)
	}
}
