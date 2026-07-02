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

	policyhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/policy"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	policyrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/policy"
)

func Policy(c *container.Container) error {
	if err := providePolicyRepository(c); err != nil {
		return err
	}
	return providePolicyServices(c)
}

func providePolicyRepository(c *container.Container) error {
	return c.Provide(func(conn *database.Connection) domain.Repository {
		return policyrepo.NewRepository(conn)
	})
}

func providePolicyServices(c *container.Container) error {
	if err := c.Provide(func(repo domain.Repository, registry appplugins.Registry, manager *cache.TTLMapManager, logger *slog.Logger, sig snapshotSignalParams) apppolicy.Creator {
		return apppolicy.NewCreator(repo, registry, manager, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, registry appplugins.Registry, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) apppolicy.Updater {
		return apppolicy.NewUpdater(repo, registry, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) apppolicy.Deleter {
		return apppolicy.NewDeleter(repo, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(apppolicy.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams) apppolicy.Scoper {
		return apppolicy.NewScoper(repo, manager, publisher, logger, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(apppolicy.NewDuplicator); err != nil {
		return err
	}

	if err := c.Provide(policyhttp.NewCreatePolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewGetPolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewListPolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewUpdatePolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewDeletePolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewGlobalPolicyHandler); err != nil {
		return err
	}
	if err := c.Provide(policyhttp.NewDuplicatePolicyHandler); err != nil {
		return err
	}
	return nil
}
