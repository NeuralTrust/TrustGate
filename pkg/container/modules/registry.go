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
	registryhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/registry"
	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	registryrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/registry"
)

func Registry(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) domain.Repository {
		return registryrepo.NewRepository(conn)
	}); err != nil {
		return err
	}

	if err := c.Provide(appregistry.NewCreator); err != nil {
		return err
	}
	if err := c.Provide(appregistry.NewUpdater); err != nil {
		return err
	}
	if err := c.Provide(appregistry.NewDeleter); err != nil {
		return err
	}
	if err := c.Provide(appregistry.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(appregistry.NewConnectionTester); err != nil {
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
	return nil
}
