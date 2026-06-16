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
	policyhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/policy"
	apppolicy "github.com/NeuralTrust/AgentGateway/pkg/app/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/database"
	policyrepo "github.com/NeuralTrust/AgentGateway/pkg/infra/repository/policy"
)

func Policy(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) domain.Repository {
		return policyrepo.NewRepository(conn)
	}); err != nil {
		return err
	}

	if err := c.Provide(apppolicy.NewCreator); err != nil {
		return err
	}
	if err := c.Provide(apppolicy.NewUpdater); err != nil {
		return err
	}
	if err := c.Provide(apppolicy.NewDeleter); err != nil {
		return err
	}
	if err := c.Provide(apppolicy.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(apppolicy.NewScoper); err != nil {
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
