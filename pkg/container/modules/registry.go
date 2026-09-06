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

package modules

import (
	"log/slog"

	registryhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry"
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storegrantdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storegrant"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	registryrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/registry"
	"go.uber.org/dig"
)

func Registry(c *container.Container) error {
	if err := provideRegistryRepository(c); err != nil {
		return err
	}
	return provideRegistryServices(c)
}

func provideRegistryRepository(c *container.Container) error {
	return c.Provide(func(conn *database.Connection, enc vaultdomain.Encrypter, appender outboxrepo.Appender) domain.Repository {
		return registryrepo.NewRepository(conn, enc, appender)
	})
}

// registryDeleterGrants carries the optional Store grant repository (full plane
// only) so a registry delete can clean its instance-level grants.
type registryDeleterGrants struct {
	dig.In
	Grants storegrantdomain.Repository `optional:"true"`
}

func provideRegistryServices(c *container.Container) error {
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger, sig snapshotSignalParams, catalog appcatalog.MCPServerCatalog, compiler appopenapi.Compiler) appregistry.Creator {
		return appregistry.NewCreator(repo, manager, logger, sig.Signaler, catalog, compiler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams, catalog appcatalog.MCPServerCatalog, compiler appopenapi.Compiler) appregistry.Updater {
		return appregistry.NewUpdater(repo, manager, publisher, logger, sig.Signaler, catalog, compiler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams, grants registryDeleterGrants) appregistry.Deleter {
		var opts []appregistry.DeleterOption
		if grants.Grants != nil {
			// Deleting a configured instance removes the Store grants scoped to it.
			opts = append(opts, appregistry.WithDependentCleaner(grants.Grants))
		}
		return appregistry.NewDeleter(repo, manager, publisher, logger, sig.Signaler, opts...)
	}); err != nil {
		return err
	}
	if err := c.Provide(appregistry.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(appregistry.NewGroupedFinder); err != nil {
		return err
	}
	if err := c.Provide(appregistry.NewConnectionTester); err != nil {
		return err
	}
	if err := c.Provide(appregistry.NewOpenAPIValidator); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewCreateRegistryHandler); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewGetRegistryHandler); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewListRegistryHandler); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewUpdateRegistryHandler); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewDeleteRegistryHandler); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewTestConnectionHandler); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewValidateOpenAPIHandler); err != nil {
		return err
	}
	return nil
}
