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

	gatewayhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/gateway"
	tenanthttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/tenant"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	gatewayrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/infra/repository/gatewaystate"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
)

func Gateway(c *container.Container) error {
	if err := provideGatewayRepository(c); err != nil {
		return err
	}
	return provideGatewayServices(c)
}

func provideGatewayRepository(c *container.Container) error {
	if err := c.Provide(func(conn *database.Connection, appender outboxrepo.Appender) *gatewayrepo.Repository {
		return gatewayrepo.NewRepository(conn, appender)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(r *gatewayrepo.Repository) domain.Repository { return r }); err != nil {
		return err
	}
	// The same repository holds the per-tenant plan caps; the snapshot compiler
	// and the Postgres planes' caps cache read them through this narrow port.
	if err := c.Provide(func(r *gatewayrepo.Repository) ratelimitdomain.TenantCapsRepository { return r }); err != nil {
		return err
	}
	// Postgres planes read the tenant caps from a copy reloaded on a timer
	// instead of querying per request. The cache is nil with the limiter off.
	return c.Provide(func(repo ratelimitdomain.TenantCapsRepository, cfg *config.Config, logger *slog.Logger) *ratelimitapp.TenantCapsCache {
		if !cfg.RateLimit.Enabled {
			return nil
		}
		return ratelimitapp.NewTenantCapsCache(repo, ratelimitapp.DefaultTenantCapsRefresh, logger)
	})
}

func provideGatewayServices(c *container.Container) error {
	if err := c.Provide(func(repo domain.Repository, registries registrydomain.Repository, manager *cache.TTLMapManager, exporterFactory appmetrics.ExporterFactory, logger *slog.Logger, sig snapshotSignalParams, cfg *config.Config) appgateway.Creator {
		return appgateway.NewCreator(repo, registries, manager, exporterFactory, logger, sig.Signaler, cfg.RateLimit.Enabled)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, registries registrydomain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, exporterFactory appmetrics.ExporterFactory, logger *slog.Logger, sig snapshotSignalParams, cfg *config.Config) appgateway.Updater {
		return appgateway.NewUpdater(repo, registries, manager, publisher, exporterFactory, logger, sig.Signaler, cfg.RateLimit.Enabled)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cc cache.Client) appgateway.StatePurger {
		return gatewaystate.NewPurger(cc.RedisClient())
	}); err != nil {
		return err
	}
	if err := c.Provide(func(repo domain.Repository, manager *cache.TTLMapManager, publisher cache.EventPublisher, logger *slog.Logger, sig snapshotSignalParams, purger appgateway.StatePurger) appgateway.Deleter {
		return appgateway.NewDeleter(repo, manager, publisher, logger, sig.Signaler, purger)
	}); err != nil {
		return err
	}
	if err := c.Provide(appgateway.NewFinder); err != nil {
		return err
	}

	if err := c.Provide(func(creator appgateway.Creator, cfg *config.Config) *gatewayhttp.CreateGatewayHandler {
		return gatewayhttp.NewCreateGatewayHandler(creator, cfg.Server.GatewayBaseDomain, cfg.Server.MCPBaseDomain)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(finder appgateway.Finder, cfg *config.Config) *gatewayhttp.GetGatewayHandler {
		return gatewayhttp.NewGetGatewayHandler(finder, cfg.Server.GatewayBaseDomain, cfg.Server.MCPBaseDomain)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(finder appgateway.Finder, cfg *config.Config) *gatewayhttp.ListGatewayHandler {
		return gatewayhttp.NewListGatewayHandler(finder, cfg.Server.GatewayBaseDomain, cfg.Server.MCPBaseDomain)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(updater appgateway.Updater, finder appgateway.Finder, cfg *config.Config) *gatewayhttp.UpdateGatewayHandler {
		return gatewayhttp.NewUpdateGatewayHandler(updater, finder, cfg.Server.GatewayBaseDomain, cfg.Server.MCPBaseDomain)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(
		repo domain.Repository,
		manager *cache.TTLMapManager,
		publisher cache.EventPublisher,
		logger *slog.Logger,
		sig snapshotSignalParams,
	) appgateway.EntitlementsRestamper {
		return appgateway.NewEntitlementsRestamper(repo, manager, publisher, sig.Signaler, logger)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(restamper appgateway.EntitlementsRestamper) *tenanthttp.RestampEntitlementsHandler {
		return tenanthttp.NewRestampEntitlementsHandler(restamper)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(deleter appgateway.Deleter, finder appgateway.Finder) *gatewayhttp.DeleteGatewayHandler {
		return gatewayhttp.NewDeleteGatewayHandler(deleter, finder)
	}); err != nil {
		return err
	}
	return nil
}
