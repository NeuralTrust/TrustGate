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

	consumerhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/consumer"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	consumerrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/consumer"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
)

func Consumer(c *container.Container) error {
	if err := provideConsumerRepository(c); err != nil {
		return err
	}
	return provideConsumerServices(c)
}

func provideConsumerRepository(c *container.Container) error {
	return c.Provide(func(conn *database.Connection, appender outboxrepo.Appender) domain.Repository {
		return consumerrepo.NewRepository(conn, appender)
	})
}

func provideConsumerServices(c *container.Container) error {
	if err := c.Provide(func(repo domain.Repository, registryRepo registrydomain.Repository, roleRepo roledomain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) appconsumer.Creator {
		return appconsumer.NewCreator(repo, registryRepo, roleRepo, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, authRepo authdomain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) appconsumer.Updater {
		return appconsumer.NewUpdater(repo, authRepo, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) appconsumer.Deleter {
		return appconsumer.NewDeleter(repo, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(appconsumer.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(appconsumer.NewDataFinder); err != nil {
		return err
	}
	if err := c.Provide(appconsumer.NewPathResolver); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, registryRepo registrydomain.Repository, roleRepo roledomain.Repository, authRepo authdomain.Repository, policyRepo policydomain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) appconsumer.Associator {
		return appconsumer.NewAssociator(repo, registryRepo, roleRepo, authRepo, policyRepo, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}

	if err := c.Provide(consumerhttp.NewCreateConsumerHandler); err != nil {
		return err
	}
	if err := c.Provide(consumerhttp.NewGetConsumerHandler); err != nil {
		return err
	}
	if err := c.Provide(consumerhttp.NewListConsumerHandler); err != nil {
		return err
	}
	if err := c.Provide(consumerhttp.NewUpdateConsumerHandler); err != nil {
		return err
	}
	if err := c.Provide(consumerhttp.NewDeleteConsumerHandler); err != nil {
		return err
	}
	if err := c.Provide(consumerhttp.NewAssociationHandler); err != nil {
		return err
	}
	return nil
}
