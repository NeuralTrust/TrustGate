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
	"github.com/NeuralTrust/TrustGate/pkg/container"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	installationrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/installation"
)

// Store wires the MCP Store's per-principal state. Installations are durable
// Postgres rows outside the config-snapshot; the data-plane read path (mirroring
// the vault's Redis path) is added when the CatalogScoper needs it.
func Store(c *container.Container) error {
	return c.Provide(func(conn *database.Connection) installationdomain.Repository {
		return installationrepo.NewRepository(conn)
	})
}
