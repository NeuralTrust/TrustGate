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
	"context"
	"log/slog"
	"net/http"

	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"

	appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"

	registryhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry"
	appa2a "github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	a2ainfra "github.com/NeuralTrust/TrustGate/pkg/infra/a2a"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
	consumerrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/consumer"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	policyrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/policy"
	registryrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trustguardscan"
	"go.uber.org/dig"
)

func Registry(c *container.Container) error {
	if err := provideRegistryRepository(c); err != nil {
		return err
	}
	return provideRegistryServices(c)
}

// registryRepositoryDeps carries the consumer and policy repositories so a
// registry delete can prune the routing JSONB and the policy mcp_scope that
// reference it in the delete's own transaction, which no foreign key can
// cascade.
//
// RUN-1501: Consumers is deliberately not `optional`. Only Registry and
// Consumer together (modules.All) provide this repository, so an unsatisfied
// field is never legitimate - it would just trade a boot failure for a
// DELETE /registries/{id} that answers 204 while leaving the dangling
// references this ticket removes, with no error and no log.
// RUN-1597: Policies follows the same rule for the mcp_scope prune.
type registryRepositoryDeps struct {
	dig.In
	Conn      *database.Connection
	Encrypter vaultdomain.Encrypter
	Sealer    *crypto.FieldSealer
	Config    *config.Config
	Appender  outboxrepo.Appender
	Consumers *consumerrepo.Repository
	Policies  *policyrepo.Repository
}

// cardPinnerParam is optional: only the Postgres registry store pins a card
// on its own, so a plane without it answers an approval with an error.
type cardPinnerParam struct {
	dig.In
	Pinner appregistry.A2ACardPinner `optional:"true"`
}

func provideRegistryRepository(c *container.Container) error {
	if err := c.Provide(func(deps registryRepositoryDeps) *registryrepo.Repository {
		return registryrepo.NewRepository(
			deps.Conn,
			deps.Encrypter,
			deps.Appender,
			registryrepo.WithFieldSealer(deps.Sealer, deps.Config.Server.StoredSecretsEncryptionEnabled),
			registryrepo.WithDeleteHook(deps.Consumers.PruneRegistryReferencesTx),
			registryrepo.WithDeleteHook(deps.Policies.PruneRegistryReferencesTx),
		)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(r *registryrepo.Repository) appregistry.A2ACardPinner {
		return r
	}); err != nil {
		return err
	}
	return c.Provide(func(r *registryrepo.Repository) domain.Repository {
		return r
	})
}

// registryDeleterCleaners carries the optional Store repositories (full plane
// only) so a registry delete can clean its instance-level grants and deny the
// pending requests for a deleted custom server.
type registryDeleterCleaners struct {
	dig.In
	Grants   storeaccessdomain.Repository         `optional:"true"`
	Everyone storeaccessdomain.EveryoneRepository `optional:"true"`
	Installs installationdomain.Repository        `optional:"true"`
}

func (p registryDeleterCleaners) options(logger *slog.Logger) []appregistry.DeleterOption {
	var opts []appregistry.DeleterOption
	if p.Grants != nil {
		opts = append(opts, appregistry.WithDependentCleaner(p.Grants))
	}
	if p.Everyone != nil {
		opts = append(opts, appregistry.WithAfterDeleteCleaner(appstore.NewEveryoneRegistryCleaner(p.Everyone)))
	}
	if denier, ok := p.Installs.(installationdomain.PendingDenier); ok {
		opts = append(opts, appregistry.WithDependentCleaner(appstore.NewDeletedServerRequests(denier, logger)))
	}
	return opts
}

// registrySaveParams carries what a save needs beyond the repository: the
// auth repository that checks an exchange's identity_id (optional, so a
// container without auths still boots and refuses targets that set it), the
// agent card reader, TrustGuard's scan of agent skills when the gateway has
// TrustGuard credentials, and the gateways a SaaS deployment checks A2A cloud
// credentials against.
type registrySaveParams struct {
	dig.In
	Auths           authdomain.Repository `optional:"true"`
	CardFetcher     appregistry.CardFetcher
	CardCredentials appregistry.CardCredentials
	Gateways        gatewaydomain.Repository
	Config          *config.Config
	// SecretRefs validates secret references on writes; absent on planes
	// without the control plane's connection store.
	SecretRefs appsecretstore.RegistryValidator `optional:"true"`
	// Materializer resolves the secret references of the auth an A2A card
	// is read with.
	Materializer appsecretref.Materializer `optional:"true"`
}

func (p registrySaveParams) options(compiler appopenapi.Compiler) []appregistry.Option {
	opts := []appregistry.Option{
		appregistry.WithOpenAPICompiler(compiler),
		appregistry.WithAgentCards(p.CardFetcher, p.CardCredentials),
	}
	if p.Materializer != nil && p.SecretRefs != nil {
		opts = append(opts, appregistry.WithCardSecrets(p.Materializer, p.SecretRefs))
	}
	tg := p.Config.TrustGuard.V2
	if scanner := trustguardscan.New(tg.BaseURL, tg.ClientID, tg.ClientSecret, tg.Timeout); scanner != nil {
		opts = append(opts, appregistry.WithSkillScanner(scanner))
	}
	if p.Auths != nil {
		opts = append(opts, appregistry.WithAuthLookup(p.Auths))
	}
	if p.Config.ConfigSync.SharedDataPlane() {
		opts = append(opts, appregistry.WithSharedDataPlane(p.Gateways))
	}
	if p.SecretRefs != nil {
		opts = append(opts, appregistry.WithSecretRefValidator(p.SecretRefs))
	}
	return opts
}

func provideAgentCards(c *container.Container) error {
	if err := c.Provide(func() appregistry.CardFetcher { return a2ainfra.NewCardFetcher(nil) }); err != nil {
		return err
	}
	if err := c.Provide(a2ainfra.NewCloudSigner); err != nil {
		return err
	}
	return c.Provide(func(provider appoauth.ProviderClient, signer *a2ainfra.CloudSigner) appregistry.CardCredentials {
		return appregistry.NewCardCredentials(func(ctx context.Context, auth *domain.MCPAuth) (string, error) {
			token, err := provider.ClientCredentials(ctx, auth)
			if err != nil {
				return "", err
			}
			return token.AccessToken, nil
		}, func(ctx context.Context, t *domain.A2ATarget, req *http.Request) error {
			return signer.Sign(ctx, t, appa2a.CacheKey{}, req)
		})
	})
}

func provideRegistryServices(c *container.Container) error {
	if err := provideAgentCards(c); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger, sig snapshotSignalParams, catalog appcatalog.MCPServerCatalog, compiler appopenapi.Compiler, save registrySaveParams) appregistry.Creator {
		return appregistry.NewCreator(repo, manager, logger, sig.Signaler, catalog, save.options(compiler)...)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams, catalog appcatalog.MCPServerCatalog, compiler appopenapi.Compiler, save registrySaveParams) appregistry.Updater {
		return appregistry.NewUpdater(repo, manager, publisher, logger, sig.Signaler, catalog, save.options(compiler)...)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams, cleaners registryDeleterCleaners) appregistry.Deleter {
		return appregistry.NewDeleter(repo, manager, publisher, logger, sig.Signaler, cleaners.options(logger)...)
	}); err != nil {
		return err
	}
	if err := c.Provide(appregistry.NewFinder); err != nil {
		return err
	}
	if err := c.Provide(appregistry.NewGroupedFinder); err != nil {
		return err
	}
	if err := c.Provide(newConnectionTester); err != nil {
		return err
	}
	if err := c.Provide(appregistry.NewOpenAPIValidator); err != nil {
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
	if err := c.Provide(registryhttp.NewValidateOpenAPIHandler); err != nil {
		return err
	}
	if err := c.Provide(func(save registrySaveParams) appregistry.PreviewAgentCard {
		return appregistry.NewPreviewAgentCard(save.options(nil)...)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, pinner cardPinnerParam, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, save registrySaveParams) appregistry.RefreshAgentCard {
		return appregistry.NewRefreshAgentCard(repo, pinner.Pinner, manager, publisher, logger, save.options(nil)...)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, pinner cardPinnerParam, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams, save registrySaveParams) appregistry.ApproveAgentCard {
		return appregistry.NewApproveAgentCard(repo, pinner.Pinner, manager, publisher, logger, sig.Signaler, save.options(nil)...)
	}); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewPreviewAgentCardHandler); err != nil {
		return err
	}
	if err := c.Provide(registryhttp.NewAgentCardHandler); err != nil {
		return err
	}
	return nil
}

type connectionTesterParams struct {
	dig.In
	Finder  appregistry.RuntimeFinder
	Locator factory.ProviderLocator
	Logger  *slog.Logger
	// Catalog is optional so a plane without the catalog module still tests
	// connections, only without catalog warnings.
	Catalog appregistry.CatalogAccessChecker `optional:"true"`
}

func newConnectionTester(p connectionTesterParams) appregistry.ConnectionTester {
	var opts []appregistry.ConnectionTesterOption
	if p.Catalog != nil {
		opts = append(opts, appregistry.WithCatalogAccessChecker(p.Catalog))
	}
	return appregistry.NewConnectionTester(p.Finder, p.Locator, p.Logger, opts...)
}
