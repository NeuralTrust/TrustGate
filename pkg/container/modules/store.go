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
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	installationrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/installation"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	storeaccessrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/storeaccess"
	"go.uber.org/dig"
)

// Store wires the MCP Store's state on the full plane: the per-principal
// installations (durable Postgres rows outside the config snapshot), the access
// grants (gateway configuration that rides the snapshot, hence the outbox
// marker), the admin grant service + handler, the registry materialiser and the
// install-approval queue handler.
func Store(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection) installationdomain.Repository {
		return installationrepo.NewRepository(conn)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(conn *database.Connection, appender outboxrepo.Appender) storeaccessdomain.Repository {
		return storeaccessrepo.NewRepository(conn, appender)
	}); err != nil {
		return err
	}
	// The Reader every Store service reads grants through; here the Postgres
	// repository, on the data plane the snapshot adapter.
	if err := c.Provide(func(repo storeaccessdomain.Repository) storeaccessdomain.Reader { return repo }); err != nil {
		return err
	}
	if err := c.Provide(func(
		repo storeaccessdomain.Repository,
		registries registrydomain.Repository,
		catalog appcatalog.MCPServerCatalog,
		sig snapshotSignalParams,
	) (appstore.GrantService, error) {
		return appstore.NewGrantService(repo, registries, catalog, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(grants appstore.GrantService) *storehttp.GrantsHandler {
		return storehttp.NewGrantsHandler(grants)
	}); err != nil {
		return err
	}
	// Per-principal access levels (All / Selected / None), evaluated live by the
	// gateway so an Access change applies at once.
	if err := c.Provide(func(conn *database.Connection, appender outboxrepo.Appender) storeaccessdomain.PolicyRepository {
		return storeaccessrepo.NewPolicyRepository(conn, appender)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo storeaccessdomain.PolicyRepository) storeaccessdomain.PolicyReader { return repo }); err != nil {
		return err
	}
	if err := c.Provide(func(repo storeaccessdomain.PolicyRepository, sig snapshotSignalParams) (appstore.PolicyService, error) {
		return appstore.NewPolicyService(repo, sig.Signaler)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(policies appstore.PolicyService) *storehttp.PoliciesHandler {
		return storehttp.NewPoliciesHandler(policies)
	}); err != nil {
		return err
	}
	// The control-plane registry materialiser: self-service installs create the
	// shared registry from the catalog through the same Creator the admin's
	// connect-from-catalog path uses. On the data plane this port is served by
	// the gRPC client instead (see ConfigSyncData); here it writes directly.
	if err := c.Provide(func(
		catalog appcatalog.MCPServerCatalog,
		registries registrydomain.Repository,
		creator appregistry.Creator,
	) (appstore.RegistryEnsurer, error) {
		return appstore.NewRegistryEnsurer(catalog, registries, creator)
	}); err != nil {
		return err
	}
	// The admin's "put this built-in on the shelf" path (consumer binding,
	// registry panel): same ensurer as a self-service install, so the registry
	// it creates is the one a user's first install would have produced.
	if err := c.Provide(func(
		catalog appcatalog.MCPServerCatalog,
		registries registrydomain.Repository,
		ensurer appstore.RegistryEnsurer,
	) (appstore.CatalogMaterializer, error) {
		return appstore.NewCatalogMaterializer(catalog, registries, ensurer)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(m appstore.CatalogMaterializer) *storehttp.MaterializeHandler {
		return storehttp.NewMaterializeHandler(m)
	}); err != nil {
		return err
	}
	if err := c.Provide(provideStoreRequestsHandler); err != nil {
		return err
	}
	return c.Provide(provideStorePrincipalHandler)
}

type storePrincipalParams struct {
	dig.In
	Catalog    appcatalog.MCPServerCatalog
	Registries registrydomain.Repository
	Installs   installationdomain.Repository
	// Vault tells whether the principal linked their own account to a
	// forwarded-auth source; absent on planes without a credential store.
	Vault vaultdomain.Repository `optional:"true"`
	// Grants, Policies, Ensurer and Gateways drive the on-behalf install: the
	// same installer and live mode decision as the user's install tool.
	Grants   storeaccessdomain.Reader
	Policies storeaccessdomain.PolicyReader
	Ensurer  appstore.RegistryEnsurer
	Gateways gatewaydomain.Repository `optional:"true"`
}

// provideStorePrincipalHandler serves the Portal's admin preview of one user's
// Store state (installs, requests, linked accounts — never token material).
func provideStorePrincipalHandler(p storePrincipalParams) (*storehttp.PrincipalHandler, error) {
	preview, err := appstore.NewPrincipalPreview(p.Installs, p.Registries, p.Catalog, p.Vault)
	if err != nil {
		return nil, err
	}
	installer, err := appstore.NewInstaller(p.Catalog, p.Registries, p.Installs, p.Grants, p.Ensurer)
	if err != nil {
		return nil, err
	}
	var gateways appstore.GatewayFinder
	if p.Gateways != nil {
		gateways = p.Gateways
	}
	onBehalf, err := appstore.NewPrincipalInstaller(installer, appstore.NewModeResolver(p.Policies), gateways)
	if err != nil {
		return nil, err
	}
	return storehttp.NewPrincipalHandler(preview, onBehalf), nil
}

type storeApprovalParams struct {
	dig.In
	Catalog    appcatalog.MCPServerCatalog
	Registries registrydomain.Repository
	Installs   installationdomain.Repository
	// Grants is where an approval lands (the requester is added to the grant);
	// the service variant also signals the snapshot rebuild.
	Grants appstore.GrantService
	// Ensurer lets an approve materialise a server nobody shelved yet.
	Ensurer appstore.RegistryEnsurer
}

func provideStoreRequestsHandler(p storeApprovalParams) (*storehttp.RequestsHandler, error) {
	opts := []appstore.ApproverOption{appstore.WithApproverEnsurer(p.Ensurer)}
	// The durable installation store keeps the decision history; a data-plane
	// proxy does not, and then History reports it unavailable.
	if history, ok := p.Installs.(installationdomain.DecisionHistory); ok {
		opts = append(opts, appstore.WithApproverHistory(history))
	}
	approver, err := appstore.NewApprover(p.Catalog, p.Registries, p.Installs, p.Grants, opts...)
	if err != nil {
		return nil, err
	}
	return storehttp.NewRequestsHandler(approver), nil
}
