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
	storehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store"
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	installationrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/installation"
	"go.uber.org/dig"
)

// Store wires the MCP Store's per-principal state. Installations are durable
// Postgres rows outside the config-snapshot; the data-plane read path (mirroring
// the vault's Redis path) is added when the CatalogScoper needs it. On the full
// plane it also wires the admin install-approval queue handler.
func Store(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) installationdomain.Repository {
		return installationrepo.NewRepository(conn)
	}); err != nil {
		return err
	}
	return c.Provide(provideStoreRequestsHandler)
}

type storeApprovalParams struct {
	dig.In
	Catalog    appcatalog.MCPServerCatalog
	Registries registrydomain.Repository
	Installs   installationdomain.Repository
}

func provideStoreRequestsHandler(p storeApprovalParams) (*storehttp.RequestsHandler, error) {
	approver, err := appstore.NewApprover(p.Catalog, p.Registries, p.Installs)
	if err != nil {
		return nil, err
	}
	return storehttp.NewRequestsHandler(approver), nil
}
