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
	"github.com/NeuralTrust/TrustGate/pkg/configsnapshot/adapters"
	"github.com/NeuralTrust/TrustGate/pkg/configsnapshot/readmodel"
	"github.com/NeuralTrust/TrustGate/pkg/configsync"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
)

func CoreData(c *container.Container) error {
	if err := provideRuntimeBase(c); err != nil {
		return err
	}
	if err := provideNilConnection(c); err != nil {
		return err
	}
	if err := provideSnapshotRepositories(c); err != nil {
		return err
	}
	return provideSnapshotServices(c)
}

func provideNilConnection(c *container.Container) error {
	return c.Provide(func() *database.Connection { return nil })
}

func provideSnapshotRepositories(c *container.Container) error {
	if err := c.Provide(func(store configsync.ConfigStore[*readmodel.Snapshot]) gatewaydomain.Repository {
		return adapters.NewGatewayRepository(store)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(store configsync.ConfigStore[*readmodel.Snapshot]) registrydomain.Repository {
		return adapters.NewRegistryRepository(store)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(store configsync.ConfigStore[*readmodel.Snapshot]) roledomain.Repository {
		return adapters.NewRoleRepository(store)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(store configsync.ConfigStore[*readmodel.Snapshot]) consumerdomain.Repository {
		return adapters.NewConsumerRepository(store)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(store configsync.ConfigStore[*readmodel.Snapshot]) policydomain.Repository {
		return adapters.NewPolicyRepository(store)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(store configsync.ConfigStore[*readmodel.Snapshot]) authdomain.Repository {
		return adapters.NewAuthRepository(store)
	}); err != nil {
		return err
	}
	return c.Provide(func(store configsync.ConfigStore[*readmodel.Snapshot]) catalogdomain.Repository {
		return adapters.NewCatalogRepository(store)
	})
}

func provideSnapshotServices(c *container.Container) error {
	if err := provideGatewayServices(c); err != nil {
		return err
	}
	if err := provideRegistryServices(c); err != nil {
		return err
	}
	if err := provideRoleServices(c); err != nil {
		return err
	}
	if err := provideConsumerServices(c); err != nil {
		return err
	}
	if err := providePolicyServices(c); err != nil {
		return err
	}
	if err := provideAuthServices(c); err != nil {
		return err
	}
	return provideCatalogServices(c)
}
