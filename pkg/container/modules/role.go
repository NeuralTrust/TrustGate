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
	rolehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/role"
	approle "github.com/NeuralTrust/TrustGate/pkg/app/role"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	rolerepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/role"
)

func Role(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) domain.Repository {
		return rolerepo.NewRepository(conn)
	}); err != nil {
		return err
	}

	if err := c.Provide(approle.NewCreator); err != nil {
		return err
	}
	if err := c.Provide(approle.NewUpdater); err != nil {
		return err
	}
	if err := c.Provide(approle.NewDeleter); err != nil {
		return err
	}
	if err := c.Provide(approle.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(approle.NewAssociator); err != nil {
		return err
	}
	if err := c.Provide(approle.NewOIDCResolver); err != nil {
		return err
	}

	if err := c.Provide(rolehttp.NewCreateRoleHandler); err != nil {
		return err
	}
	if err := c.Provide(rolehttp.NewGetRoleHandler); err != nil {
		return err
	}
	if err := c.Provide(rolehttp.NewListRoleHandler); err != nil {
		return err
	}
	if err := c.Provide(rolehttp.NewUpdateRoleHandler); err != nil {
		return err
	}
	if err := c.Provide(rolehttp.NewDeleteRoleHandler); err != nil {
		return err
	}
	if err := c.Provide(rolehttp.NewAssociationHandler); err != nil {
		return err
	}
	return nil
}
