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
	consumerhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/consumer"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	consumerrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/consumer"
)

func Consumer(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) domain.Repository {
		return consumerrepo.NewRepository(conn)
	}); err != nil {
		return err
	}

	if err := c.Provide(appconsumer.NewCreator); err != nil {
		return err
	}
	if err := c.Provide(appconsumer.NewUpdater); err != nil {
		return err
	}
	if err := c.Provide(appconsumer.NewDeleter); err != nil {
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
	if err := c.Provide(appconsumer.NewAssociator); err != nil {
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
