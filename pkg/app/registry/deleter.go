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

// DependentCleaner removes state that hangs off a registry and must not outlive
// it — today the MCP Store's instance-level access grants on that registry.
type DependentCleaner interface {
	DeleteByRegistry(ctx context.Context, gatewayID ids.GatewayID, registryID ids.RegistryID) error
}

// DeleterOption tunes NewDeleter.
type DeleterOption func(*deleter)

// WithDependentCleaner runs the cleaner after a successful delete. A cleanup
// failure is logged, not returned: the registry is already gone and a dangling
// grant on a missing registry grants nothing.
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
	if err := d.repo.Delete(ctx, gatewayID, id); err != nil {
		return err
	}
	d.memoryCache.Delete(id.String())
	for _, cleaner := range d.cleaners {
		if err := cleaner.DeleteByRegistry(ctx, gatewayID, id); err != nil && d.logger != nil {
			d.logger.WarnContext(ctx, "registry: dependent cleanup failed after delete",
				slog.String("registry_id", id.String()), slog.String("error", err.Error()))
		}
	}
	invalidation.Registry(ctx, d.publisher, d.logger, existing.GatewayID, existing.ID)
	if d.signaler != nil {
		d.signaler.Signal(ctx)
	}
	return nil
}
